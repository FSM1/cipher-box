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
// KNOWN BLOCKER (read before running): as of this writing, NO call site in
// the desktop binary (`apps/desktop/src-tauri/src/fuse/mod.rs`) ever invokes
// `CipherBoxFS::refresh_sent_shares`. `sent_shares` is seeded once at mount
// init to `SentSharesCache::empty()` (non-authoritative) and never
// refreshed. Because `gate_scope_exit`/`run_scope_exit_gate`
// (`crates/fuse/src/write_ops/grant_scope.rs`) fails CLOSED (EIO) while the
// cache is non-authoritative (D-15a), EVERY delete/rename on a real mount --
// private or shared -- currently returns EIO, unconditionally. Part 1 of
// this script (the shared-scope-exit leg) CANNOT pass until a follow-up
// wires a `refresh_sent_shares()` call into the mount lifecycle (mount init
// + periodic background refresh, mirroring the existing
// `spawn_bin_entry_publish` pattern in `fuse/mod.rs`). Part 2 (private
// delete) is ALSO blocked by the same gap, since the private path hits the
// identical non-authoritative-cache gate before ever reaching the
// private/shared branch. See this plan's SUMMARY.md for the full writeup.
// This script fails loudly and diagnostically (not silently) if that gap is
// still open, distinguishing it from a genuine regression.
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
  attempts = 18,
  delayMs = 5000
): Promise<SealedChildRef> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const folder = await loadFolderMetadata({
        ipnsName: parentIpnsName,
        folderKey: parentReadKey,
        ctx,
      });
      const match = folder?.metadata.children?.find((c) => c.name === name);
      if (match) return match;
    } catch (err) {
      lastError = err;
    }
    await sleep(delayMs);
  }
  throw new Error(
    `pollFindChild: "${name}" never appeared under ${parentIpnsName} after ${attempts} attempts` +
      (lastError ? ` (last error: ${String(lastError)})` : '')
  );
}

/** Poll an IPNS name's resolved sequence number until it exceeds `floor`. */
async function pollSequenceBump(
  ipnsName: string,
  floor: bigint,
  ctx: SdkContext,
  attempts = 18,
  delayMs = 5000
): Promise<bigint> {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const resolved = await resolveIpnsRecord(ipnsName, ctx);
    if (resolved && resolved.sequenceNumber > floor) {
      return resolved.sequenceNumber;
    }
    await sleep(delayMs);
  }
  throw new Error(
    `pollSequenceBump: sequence for ${ipnsName} never exceeded ${floor} after ${attempts} attempts`
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

    const seqBeforeDelete = await resolveIpnsRecord(grantRootIpnsName, ownerCtx).then((r) => {
      if (!r) throw new Error(`grant-root ${grantRootIpnsName} did not resolve before delete`);
      return r.sequenceNumber;
    });

    // Grant Bob read access to the shared folder via ECIES (v3 CreateShareDto).
    const wrappedForBob = await wrapKey(sharedFolderReadKey, bobPublicKey);
    const shareRes = await axiosInstance.post('/shares', {
      recipientPublicKey: '0x' + bytesToHex(bobPublicKey),
      readDescriptorRef: bytesToHex(wrappedForBob),
      rootNodeId: grantRootNodeId,
      rootIpnsName: grantRootIpnsName,
    });
    const shareId: string = shareRes.data.shareId;
    console.log(`Created share ${shareId} for ${bobEmail} rooted at ${grantRootIpnsName}`);

    // Bob unwraps his copy of the key WHILE the share is still active -- a
    // positive control proving the grant genuinely worked before revocation
    // (so "cut off after rotation" isn't just "never worked").
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
    const bobCouldReadBeforeRevocation = await canRead(grantRootIpnsName, bobFolderReadKey, bobCtx);
    if (!bobCouldReadBeforeRevocation) {
      throw new Error(
        'PRECONDITION FAILED: Bob could not decrypt the shared folder BEFORE revocation -- ' +
          'the share never worked, so a post-rotation failure below would not prove anything'
      );
    }
    console.log('PASS: Bob could decrypt the shared folder before revocation (positive control)');

    // Revoke Bob's grant BEFORE the scope-exit mutation.
    const revokeRes = await axiosInstance.delete(`/shares/${shareId}`);
    if (revokeRes.status !== 204) {
      throw new Error(`Revoking share ${shareId} failed with status ${revokeRes.status}`);
    }
    console.log(`Revoked share ${shareId}`);

    // Give the desktop mount's sent_shares cache every opportunity to
    // observe the (now-revoked) grant before the scope-exit mutation. NOTE:
    // as of this writing NOTHING calls CipherBoxFS::refresh_sent_shares, so
    // this delete is expected to EIO until that gap is closed (see header).
    await sleep(15000);

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
          '  This is EXPECTED to EIO today: no call site in apps/desktop/src-tauri/src/fuse/mod.rs ' +
          'ever invokes CipherBoxFS::refresh_sent_shares, so sent_shares never becomes authoritative ' +
          'and gate_scope_exit fails closed unconditionally (see script header + this plan SUMMARY.md). ' +
          'If refresh_sent_shares HAS since been wired in and this still fails, treat it as a genuine ' +
          'regression, not the known gap.'
      );
      failed = true;
    } else {
      console.log('PASS: shared-scope-exit delete completed with no EIO');

      const seqAfterDelete = await pollSequenceBump(grantRootIpnsName, seqBeforeDelete, ownerCtx);
      if (seqAfterDelete === seqBeforeDelete + 1n) {
        console.log(
          `PASS: grant-root ${grantRootIpnsName} sequence bumped by exactly 1 ` +
            `(${seqBeforeDelete} -> ${seqAfterDelete}) -- exactly one rotation publish`
        );
      } else {
        console.error(
          `FAIL: grant-root ${grantRootIpnsName} sequence bumped by ${seqAfterDelete - seqBeforeDelete}, ` +
            `expected exactly 1 (${seqBeforeDelete} -> ${seqAfterDelete})`
        );
        failed = true;
      }

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
          'FAIL: the pre-rotation read key still decrypts the grant-root -- no rotation occurred'
        );
        failed = true;
      }

      const bobCanReadAfterRotation = await canRead(grantRootIpnsName, bobFolderReadKey, bobCtx);
      if (!bobCanReadAfterRotation) {
        console.log('PASS: revoked recipient (Bob) can no longer decrypt the rotated subtree');
      } else {
        console.error(
          'FAIL: revoked recipient (Bob) can STILL decrypt the rotated subtree -- revocation bypass'
        );
        failed = true;
      }
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
          '  Same known blocker as Part A applies here too -- a non-authoritative sent_shares ' +
          'cache fails EVERY delete closed, private or shared, until refresh_sent_shares is wired in.'
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
