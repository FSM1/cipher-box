#!/usr/bin/env node
// shared-scope-exit-rotation.mts -- Desktop-e2e acceptance leg for D-16
// (2026-07-07-fuse-shared-scope-exit-rotation-live-wiring.md, folded into
// Phase 70.1 SC#8).
//
// Asserts, on a REAL mounted FUSE filesystem:
//   1. A shared-scope-exit delete on a node with an active covering grant
//      completes successfully (no EIO).
//   2. Exactly ONE rotate_read_from_node rotation is published for the
//      grant-root (assert via an IPNS sequence-number bump of exactly +1 on
//      the grant-root's own ipnsName).
//   3. A revoked recipient can no longer read the rotated subtree (the old,
//      pre-rotation read key AEAD-fails against the post-rotation body).
//   4. A private delete (no covering grant anywhere in the ancestor chain)
//      produces ZERO rotation publishes -- the parent's read key is
//      UNCHANGED after the delete (only a plain relink republish occurs).
//
// MOUNT-INIT DEPENDENCY (read before diagnosing an EIO): the scope-exit gate
// (`gate_scope_exit`/`run_scope_exit_gate`, `crates/fuse/src/write_ops/
// grant_scope.rs`) fails CLOSED (EIO) until `CipherBoxFS.sent_shares` is
// AUTHORITATIVE, i.e. until a `/shares/sent` refresh has succeeded this
// session. The desktop mount now seeds that cache at mount init (bounded,
// best-effort) and drives a 30s periodic background refresh
// (`spawn_periodic_sent_shares_refresh`, wired in `fuse/mod.rs` +
// `fuse/windows/mod.rs`). So a delete/rename issued in the first moments
// after mount -- before the init refresh completes, or if it failed and the
// periodic task has not yet recovered -- can transiently EIO by design; the
// retry loops below (6 attempts x 15s) absorb that window. A PERSISTENT EIO
// across all retries means either the init+periodic refresh is failing to
// reach the relay (check the desktop log for "sent-shares refresh failed")
// or a genuine gate regression -- NOT the old "never-wired" gap, which is
// now closed. This script fails loudly and diagnostically, never silently.
//
// Usage: node node_modules/tsx/dist/cli.mjs shared-scope-exit-rotation.mts \
//          --mount <path> --api-url <url>
// Env:   TEST_SECRET (required) -- shared secret for /auth/test-login.

import { mkdirSync, writeFileSync, rmSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import {
  loadVaultKeyBlob,
  loadFolderMetadata,
  resolveIpnsRecord,
  fetchFromIpfs,
  type SdkContext,
} from '@cipherbox/sdk-core';
import { unsealChildReadKey, type PublishedNode, type SealedChildRef } from '@cipherbox/core';
import { wrapKey, unwrapKey, bytesToHex, hexToBytes, clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../e2e-helpers/auth';

// The desktop launches with --dev-key, which maps to this fixed test identity.
const OWNER_EMAIL = 'dev-key@cipherbox.local';

interface Args {
  mount: string;
  apiUrl: string;
  secret: string;
}

function parseArgs(argv: string[]): Args {
  const values = parseCliArgs(argv);
  const mount =
    values['mount'] || join(process.env.HOME || process.env.USERPROFILE || '', 'CipherBox');
  const apiUrl = values['api-url'] || 'http://localhost:3000';
  const secret = process.env.TEST_SECRET;
  if (!secret) {
    throw new Error(
      'Usage: shared-scope-exit-rotation.mts --mount <path> --api-url <url> (requires TEST_SECRET env var)'
    );
  }
  return { mount, apiUrl, secret };
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// Nudge the mount so FUSE re-resolves metadata (mirrors test-move-content.ts).
function nudge(...paths: string[]): void {
  for (const p of paths) {
    try {
      statSync(p);
    } catch {
      /* not visible yet */
    }
    try {
      readdirSync(p);
    } catch {
      /* not a dir / not visible yet */
    }
  }
}

/**
 * Fetch an IPNS name's raw node/v3 PublishedNode envelope. The envelope's
 * id/kind/generation are plaintext AAD inputs (mirrors
 * packages/sdk-core/scripts/verify-filepointer.mts).
 */
async function fetchPublishedNode(ipnsName: string, ctx: SdkContext): Promise<PublishedNode> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) {
    throw new Error(`IPNS record not found for ${ipnsName}`);
  }
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}

/**
 * Derive a child node's read key from its SealedChildRef under the parent
 * read key (mirrors verify-filepointer.mts's deriveChildReadKey).
 */
async function deriveChildReadKey(
  childRef: SealedChildRef,
  parentReadKey: Uint8Array,
  ctx: SdkContext
): Promise<{ childReadKey: Uint8Array; childPublished: PublishedNode }> {
  const childPublished = await fetchPublishedNode(childRef.ipnsName, ctx);
  const childReadKey = await unsealChildReadKey(
    childRef.readKeySealed,
    parentReadKey,
    childPublished.id,
    childPublished.kind,
    childRef.generation
  );
  return { childReadKey, childPublished };
}

/** Poll a parent folder's children until `name` appears, or throw. */
async function pollFindChild(
  parentIpnsName: string,
  parentReadKey: Uint8Array,
  name: string,
  ctx: SdkContext,
  // Budget widened (18->40 @5s = 200s) after CI showed the two-hop publish chain
  // (own IPNS publish + parent children-list republish) can take ~40-47s even on a
  // warm machine — slow CI runners (cold Kubo, shared vCPUs) blow a 90s budget.
  attempts = 40,
  delayMs = 5000
): Promise<SealedChildRef> {
  const started = Date.now();
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const folder = await loadFolderMetadata({
        ipnsName: parentIpnsName,
        folderKey: parentReadKey,
        ctx,
      });
      const match = folder?.metadata.children?.find((c) => c.name === name);
      if (match) {
        console.log(
          `  pollFindChild: "${name}" appeared after ${((Date.now() - started) / 1000).toFixed(1)}s (attempt ${attempt}/${attempts})`
        );
        return match;
      }
    } catch (err) {
      lastError = err;
    }
    await sleep(delayMs);
  }
  throw new Error(
    `pollFindChild: "${name}" never appeared under ${parentIpnsName} after ${attempts} attempts ` +
      `(${((Date.now() - started) / 1000).toFixed(1)}s)` +
      (lastError ? ` (last error: ${String(lastError)})` : '')
  );
}

/** Poll an IPNS name's resolved sequence number until it exceeds `floor`. */
async function pollSequenceBump(
  ipnsName: string,
  floor: bigint,
  ctx: SdkContext,
  attempts = 40,
  delayMs = 5000
): Promise<bigint> {
  const started = Date.now();
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const resolved = await resolveIpnsRecord(ipnsName, ctx);
    if (resolved && resolved.sequenceNumber > floor) {
      console.log(
        `  pollSequenceBump: ${ipnsName} exceeded ${floor} -> ${resolved.sequenceNumber} after ${((Date.now() - started) / 1000).toFixed(1)}s (attempt ${attempt}/${attempts})`
      );
      return resolved.sequenceNumber;
    }
    await sleep(delayMs);
  }
  throw new Error(
    `pollSequenceBump: sequence for ${ipnsName} never exceeded ${floor} after ${attempts} attempts ` +
      `(${((Date.now() - started) / 1000).toFixed(1)}s)`
  );
}

/** True if `folderKey` can still successfully decrypt `ipnsName`'s body. */
async function canRead(ipnsName: string, folderKey: Uint8Array, ctx: SdkContext): Promise<boolean> {
  try {
    const result = await loadFolderMetadata({ ipnsName, folderKey, ctx });
    return result !== null;
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const tag = `${process.pid}-${Date.now()}`;
  let failed = false;

  console.log('=== Shared scope-exit rotation acceptance (D-16) ===');
  console.log(`Mount point: ${args.mount}`);
  console.log(`API URL:     ${args.apiUrl}`);

  const ownerAuth = await authenticate(args.apiUrl, OWNER_EMAIL, args.secret);
  const ownerCtx = buildSdkContext(args.apiUrl, ownerAuth.accessToken);
  const ownerPrivateKey = hexToBytes(ownerAuth.privateKeyHex);

  const bobEmail = `shared-scope-exit-bob-${tag}@cipherbox.local`;
  const bobAuth = await authenticate(args.apiUrl, bobEmail, args.secret);
  const bobCtx = buildSdkContext(args.apiUrl, bobAuth.accessToken);
  if (!bobAuth.publicKeyHex || !bobAuth.privateKeyHex) {
    throw new Error('bob test-login response missing publicKeyHex/privateKeyHex');
  }
  const bobPublicKey = hexToBytes(bobAuth.publicKeyHex);
  const bobPrivateKey = hexToBytes(bobAuth.privateKeyHex);

  const axiosInstance = ownerCtx.axiosInstance;
  if (!axiosInstance) {
    throw new Error('owner SdkContext missing axiosInstance');
  }

  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName: string = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey: ownerPrivateKey, ctx: ownerCtx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }
  const { rootReadKey } = vaultKeyBlob;

  try {
    // -----------------------------------------------------------------
    // PART A: shared-scope-exit delete -> exactly ONE grant-root rotation,
    // revoked recipient cut off.
    // -----------------------------------------------------------------
    console.log('\n--- Part A: shared scope-exit rotation ---');
    const sharedFolderName = `SharedGrant-${tag}`;
    const sharedFileName = 'secret.txt';
    const sharedFileContent = 'covered scope-exit content must rotate on delete';

    mkdirSync(join(args.mount, sharedFolderName), { recursive: true });
    await sleep(3000);
    nudge(args.mount);
    writeFileSync(join(args.mount, sharedFolderName, sharedFileName), sharedFileContent);
    await sleep(5000);
    nudge(join(args.mount, sharedFolderName));

    const sharedRef = await pollFindChild(rootIpnsName, rootReadKey, sharedFolderName, ownerCtx);
    const { childReadKey: sharedFolderReadKey, childPublished: sharedFolderPublished } =
      await deriveChildReadKey(sharedRef, rootReadKey, ownerCtx);
    const grantRootIpnsName = sharedRef.ipnsName;
    const grantRootNodeId = sharedFolderPublished.id;

    // Confirm the file landed inside the shared folder before measuring.
    await pollFindChild(grantRootIpnsName, sharedFolderReadKey, sharedFileName, ownerCtx);

    // Grant Bob read access to the shared folder via ECIES (v3 CreateShareDto).
    // The grant MUST stay ACTIVE through the delete: the scope-exit gate keys
    // off the mount's sent_shares cache (GET /shares/sent), and revoke is a
    // hard DELETE, so revoking here would drop the covering grant and the
    // delete would look PRIVATE (no rotation). Bob is cut off by the ROTATION
    // itself (the desktop rotation re-mints the folder key and, since
    // query_grants_rooted_at is a desktop no-op, does NOT re-wrap Bob's grant)
    // — the explicit revoke below is cleanup after the rotation is proven.
    const wrappedForBob = await wrapKey(sharedFolderReadKey, bobPublicKey);
    const shareRes = await axiosInstance.post('/shares', {
      recipientPublicKey: '0x' + bytesToHex(bobPublicKey),
      readDescriptorRef: bytesToHex(wrappedForBob),
      rootNodeId: grantRootNodeId,
      rootIpnsName: grantRootIpnsName,
    });
    const shareId: string = shareRes.data.shareId;
    console.log(`Created share ${shareId} for ${bobEmail} rooted at ${grantRootIpnsName}`);

    // Bob unwraps his copy of the key WHILE the share is active -- a positive
    // control proving the grant genuinely worked (so "cut off after rotation"
    // isn't just "never worked").
    const receivedRes = await bobCtx.axiosInstance!.get('/shares/received');
    const receivedShare = (
      receivedRes.data.shares as Array<{ shareId: string; readDescriptorRef: string }>
    ).find((s) => s.shareId === shareId);
    if (!receivedShare) {
      throw new Error('Bob does not see the newly created share in /shares/received');
    }
    const bobFolderReadKey = await unwrapKey(
      hexToBytes(receivedShare.readDescriptorRef),
      bobPrivateKey
    );
    const bobCouldReadWhileActive = await canRead(grantRootIpnsName, bobFolderReadKey, bobCtx);
    if (!bobCouldReadWhileActive) {
      throw new Error(
        'PRECONDITION FAILED: Bob could not decrypt the shared folder while the share was ' +
          'ACTIVE -- the share never worked, so a post-rotation failure below would prove nothing'
      );
    }
    console.log(
      'PASS: Bob could decrypt the shared folder while the grant was active (positive control)'
    );

    // Wait for the mount's sent_shares cache to observe the ACTIVE grant
    // (periodic refresh runs every 30s; mount init also seeds it once). One
    // full cycle guarantees the just-created share is visible to the gate, so
    // the covered scope-exit actually rotates rather than looking private.
    await sleep(35000);

    // Measure the grant-root sequence immediately before the delete (after the
    // folder/file publishes have settled) so the +1 assertion isolates the
    // rotation's single publish.
    const seqBeforeDelete = await resolveIpnsRecord(grantRootIpnsName, ownerCtx).then((r) => {
      if (!r) throw new Error(`grant-root ${grantRootIpnsName} did not resolve before delete`);
      return r.sequenceNumber;
    });

    // Perform the covered scope-exit delete THROUGH THE MOUNT.
    const ATTEMPTS = 6;
    const RETRY_DELAY_MS = 15000;
    let deleteSucceeded = false;
    let lastDeleteError: unknown;
    for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
      try {
        rmSync(join(args.mount, sharedFolderName, sharedFileName));
        deleteSucceeded = true;
        break;
      } catch (err) {
        lastDeleteError = err;
        nudge(join(args.mount, sharedFolderName));
        await sleep(RETRY_DELAY_MS);
      }
    }

    if (!deleteSucceeded) {
      console.error(
        `FAIL: shared-scope-exit delete of ${sharedFileName} did not succeed after ${ATTEMPTS} attempts. ` +
          `Last error: ${String(lastDeleteError)}\n` +
          "  A PERSISTENT EIO here means the mount's sent_shares cache never became authoritative " +
          '(check the desktop log for "sent-shares refresh failed"/"timed out" — the relay was ' +
          'unreachable at mount init AND across the periodic refresh cycles), or a genuine ' +
          'scope-exit gate regression. See the script header + this plan SUMMARY.md.'
      );
      failed = true;
    } else {
      console.log('PASS: shared-scope-exit delete completed with no EIO');

      // COALESCED PUBLISH COUNT (70.1-13a): a covered scope-exit delete of the
      // grant-root's only child now publishes the grant-root EXACTLY ONCE — the
      // rotation republishes it with the post-delete (empty) child list under
      // the new key as the single authoritative publish, and the plain
      // stale-key relink is SUPPRESSED. Before the fix this was +2 (rotate_one +
      // batched republish_parent) followed by a +1 old-key relink (the
      // revocation bypass). The SECURITY invariants below (pre-rotation key
      // dead, Bob cut off) are the primary D-16 gate; this count check guards
      // the coalescing.
      const seqAfterDelete = await pollSequenceBump(grantRootIpnsName, seqBeforeDelete, ownerCtx);
      if (seqAfterDelete === seqBeforeDelete + 1n) {
        console.log(
          `PASS: grant-root ${grantRootIpnsName} sequence bumped by exactly 1 ` +
            `(${seqBeforeDelete} -> ${seqAfterDelete}) -- coalesced single rotation publish`
        );
      } else {
        console.error(
          `FAIL: grant-root ${grantRootIpnsName} sequence bumped by ${seqAfterDelete - seqBeforeDelete}, ` +
            `expected exactly 1 (${seqBeforeDelete} -> ${seqAfterDelete}) -- coalescing regressed ` +
            '(rotation double-published, or the stale-key relink was not suppressed)'
        );
        failed = true;
      }

      // SECURITY INVARIANT 1: the newest grant-root record is NOT decryptable by
      // the pre-rotation key. This is resolved AFTER pollSequenceBump has
      // settled on the post-delete record, so it reflects the final published
      // state (not a transient mid-rotation record).
      const preRotationKeyStillWorks = await canRead(
        grantRootIpnsName,
        sharedFolderReadKey,
        ownerCtx
      );
      if (!preRotationKeyStillWorks) {
        console.log(
          'PASS: the pre-rotation read key no longer decrypts the grant-root (key rotated)'
        );
      } else {
        console.error(
          'FAIL: the pre-rotation read key still decrypts the grant-root -- the newest record ' +
            'is sealed under the OLD key (stale-key relink revocation bypass regressed)'
        );
        failed = true;
      }

      // SECURITY INVARIANT 2: the revoked recipient (Bob) is cut off. Bob's key
      // is byte-identical to the owner's pre-rotation key, so this fails iff the
      // newest published record is under the old key (the bypass).
      const bobCanReadAfterRotation = await canRead(grantRootIpnsName, bobFolderReadKey, bobCtx);
      if (!bobCanReadAfterRotation) {
        console.log(
          'PASS: recipient (Bob) can no longer decrypt the rotated subtree with the key that ' +
            'worked while active -- the scope-exit rotation cut the reader off'
        );
      } else {
        console.error(
          'FAIL: recipient (Bob) can STILL decrypt the rotated subtree -- revocation bypass'
        );
        failed = true;
      }
    }

    // Cleanup: revoke Bob's (now-stale) grant. The rotation above already cut
    // Bob off; this hard-deletes the share row so a later re-run starts clean.
    const revokeRes = await axiosInstance.delete(`/shares/${shareId}`);
    if (revokeRes.status !== 204) {
      console.warn(`Cleanup: revoking share ${shareId} returned ${revokeRes.status} (non-fatal)`);
    }

    clearBytes(sharedFolderReadKey);
    clearBytes(bobFolderReadKey);

    // -----------------------------------------------------------------
    // PART B: private delete -> ZERO rotation publishes.
    // -----------------------------------------------------------------
    console.log('\n--- Part B: private delete, zero rotation ---');
    const privateFolderName = `PrivateFolder-${tag}`;
    const privateFileName = 'private.txt';

    mkdirSync(join(args.mount, privateFolderName), { recursive: true });
    await sleep(3000);
    nudge(args.mount);
    writeFileSync(
      join(args.mount, privateFolderName, privateFileName),
      'never shared, must not rotate'
    );
    await sleep(5000);
    nudge(join(args.mount, privateFolderName));

    const privateRef = await pollFindChild(rootIpnsName, rootReadKey, privateFolderName, ownerCtx);
    const { childReadKey: privateFolderReadKey } = await deriveChildReadKey(
      privateRef,
      rootReadKey,
      ownerCtx
    );
    const privateFolderIpnsName = privateRef.ipnsName;

    await pollFindChild(privateFolderIpnsName, privateFolderReadKey, privateFileName, ownerCtx);

    const seqBeforePrivateDelete = await resolveIpnsRecord(privateFolderIpnsName, ownerCtx).then(
      (r) => {
        if (!r)
          throw new Error(`private folder ${privateFolderIpnsName} did not resolve before delete`);
        return r.sequenceNumber;
      }
    );

    let privateDeleteSucceeded = false;
    let lastPrivateDeleteError: unknown;
    for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
      try {
        rmSync(join(args.mount, privateFolderName, privateFileName));
        privateDeleteSucceeded = true;
        break;
      } catch (err) {
        lastPrivateDeleteError = err;
        nudge(join(args.mount, privateFolderName));
        await sleep(RETRY_DELAY_MS);
      }
    }

    if (!privateDeleteSucceeded) {
      console.error(
        `FAIL: private delete of ${privateFileName} did not succeed after ${ATTEMPTS} attempts. ` +
          `Last error: ${String(lastPrivateDeleteError)}\n` +
          '  The scope-exit gate fails closed for private deletes too until sent_shares is ' +
          'authoritative; by Part B the mount has been up >1min, so a persistent EIO here means ' +
          'the sent_shares refresh is not reaching the relay, or a gate regression.'
      );
      failed = true;
    } else {
      console.log('PASS: private delete completed with no EIO');

      const seqAfterPrivateDelete = await pollSequenceBump(
        privateFolderIpnsName,
        seqBeforePrivateDelete,
        ownerCtx
      );
      if (seqAfterPrivateDelete === seqBeforePrivateDelete + 1n) {
        console.log(
          `PASS: private folder ${privateFolderIpnsName} sequence bumped by exactly 1 (plain relink republish)`
        );
      } else {
        console.error(
          `FAIL: private folder ${privateFolderIpnsName} sequence bumped by ` +
            `${seqAfterPrivateDelete - seqBeforePrivateDelete}, expected exactly 1`
        );
        failed = true;
      }

      const privateKeyStillWorks = await canRead(
        privateFolderIpnsName,
        privateFolderReadKey,
        ownerCtx
      );
      if (privateKeyStillWorks) {
        console.log(
          'PASS: private folder read key UNCHANGED after delete (zero rotation publishes)'
        );
      } else {
        console.error(
          'FAIL: private folder read key no longer works after delete -- an unexpected rotation occurred'
        );
        failed = true;
      }
    }

    clearBytes(privateFolderReadKey);
  } finally {
    clearBytes(rootReadKey);
    clearBytes(ownerPrivateKey);
    clearBytes(bobPrivateKey);
  }

  console.log(`\n=== Shared scope-exit rotation acceptance: ${failed ? 'FAILED' : 'PASSED'} ===`);
  process.exit(failed ? 1 : 0);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
