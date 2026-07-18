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

import { mkdirSync, writeFileSync, rmSync, renameSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import {
  loadVaultKeyBlob,
  loadFolderMetadata,
  resolveFileMetadata,
  resolveIpnsRecord,
  fetchFromIpfs,
  updateFolderMetadataAndPublish,
  appendRecipientPin,
  type SdkContext,
} from '@cipherbox/sdk-core';
import {
  unsealChildReadKey,
  unsealChildWriteKey,
  unsealNode,
  type PublishedNode,
  type SealedChildRef,
} from '@cipherbox/core';
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
  // Paths to nudge (statSync/readdirSync) at the START of every poll iteration.
  // A file written through the mount enqueues its parent-folder republish in the
  // FUSE crate's EDGE-TRIGGERED publish_queue, which only drains when a FUSE op
  // reaches `drain_upload_completions`/`flush_publish_queue` (crates/fuse/src/fs.rs).
  // On FUSE-T (macOS/SMB) the file `release` that enqueues it can be deferred tens
  // of seconds past the write — landing AFTER this script stops touching the mount
  // — so polling the folder's IPNS alone (no mount I/O) can wait forever for a
  // child that is stuck un-republished. Nudging the folder each iteration
  // generates the FUSE op that drains the queue, mirroring a real client that
  // keeps using the mount. (The product-side backstop for a fully-idle mount lives
  // in apps/desktop fuse mount: the fuse-publish-pump thread.)
  nudgePaths: string[] = [],
  // Budget widened (18->40 @5s = 200s) after CI showed the two-hop publish chain
  // (own IPNS publish + parent children-list republish) can take ~40-47s even on a
  // warm machine — slow CI runners (cold Kubo, shared vCPUs) blow a 90s budget.
  attempts = 40,
  delayMs = 5000
): Promise<SealedChildRef> {
  const started = Date.now();
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    if (nudgePaths.length > 0) {
      nudge(...nudgePaths);
    }
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

/** True if `fileReadKey` can still successfully decrypt the file node at `ipnsName`. */
async function canReadFile(
  ipnsName: string,
  fileReadKey: Uint8Array,
  ctx: SdkContext
): Promise<boolean> {
  try {
    await resolveFileMetadata(ipnsName, fileReadKey, ctx);
    return true;
  } catch {
    return false;
  }
}

/**
 * Authenticate a fresh test-login recipient identity for the deep/retained-
 * vs-revoked and rename-overwrite legs (Parts C/D). Mirrors Part A's
 * inline Bob setup, factored out since Parts C/D need four such identities
 * (Eve/Carol/Frank/Grace) instead of one.
 */
async function authenticateRecipient(
  apiUrl: string,
  label: string,
  tag: string,
  secret: string
): Promise<{ ctx: SdkContext; publicKey: Uint8Array; privateKey: Uint8Array; email: string }> {
  const email = `shared-scope-exit-${label}-${tag}@cipherbox.local`;
  const auth = await authenticate(apiUrl, email, secret);
  const ctx = buildSdkContext(apiUrl, auth.accessToken);
  if (!auth.publicKeyHex || !auth.privateKeyHex) {
    throw new Error(`${label} test-login response missing publicKeyHex/privateKeyHex`);
  }
  return {
    ctx,
    publicKey: hexToBytes(auth.publicKeyHex),
    privateKey: hexToBytes(auth.privateKeyHex),
    email,
  };
}

/**
 * Poll a recipient's `/shares/received` list until `shareId`'s
 * `encryptedReadKey` has genuinely changed from `priorEncryptedReadKey` --
 * proves `FuseRotationDeps::update_grant` (74-05) actually re-minted this
 * grant to a new generation, not merely that the endpoint returned 200.
 */
async function pollGrantRemint(
  recipientCtx: SdkContext,
  shareId: string,
  priorEncryptedReadKey: string,
  attempts = 40,
  delayMs = 5000
): Promise<{ encryptedReadKey: string; rootGeneration: string }> {
  const axios = recipientCtx.axiosInstance;
  if (!axios) {
    throw new Error('pollGrantRemint: recipient SdkContext missing axiosInstance');
  }
  const started = Date.now();
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const receivedRes = await axios.get('/shares/received');
    const shares = receivedRes.data.shares as Array<{
      shareId: string;
      encryptedReadKey: string;
      rootGeneration: string;
    }>;
    const match = shares.find((s) => s.shareId === shareId);
    if (match && match.encryptedReadKey !== priorEncryptedReadKey) {
      console.log(
        `  pollGrantRemint: share ${shareId} re-minted (generation -> ${match.rootGeneration}) ` +
          `after ${((Date.now() - started) / 1000).toFixed(1)}s (attempt ${attempt}/${attempts})`
      );
      return { encryptedReadKey: match.encryptedReadKey, rootGeneration: match.rootGeneration };
    }
    await sleep(delayMs);
  }
  throw new Error(
    `pollGrantRemint: share ${shareId} was never re-minted (encryptedReadKey unchanged) after ` +
      `${attempts} attempts (${((Date.now() - started) / 1000).toFixed(1)}s)`
  );
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

  // Part C (deep + retained-vs-revoked) and Part D (rename-overwrite dest
  // gate) each need a revoked-recipient/retained-recipient pair. Authenticate
  // all four up front, alongside Bob, so their private keys are declared at
  // this function's top scope and reachable from the shared `finally` below
  // (a `const` declared inside `try { ... }` is NOT visible in `finally`).
  const eve = await authenticateRecipient(args.apiUrl, 'eve', tag, args.secret);
  const carol = await authenticateRecipient(args.apiUrl, 'carol', tag, args.secret);
  const frank = await authenticateRecipient(args.apiUrl, 'frank', tag, args.secret);
  const grace = await authenticateRecipient(args.apiUrl, 'grace', tag, args.secret);

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
  const { rootReadKey, rootWriteKey } = vaultKeyBlob;

  /**
   * Pin a recipient's pubkey onto a shared grant-root folder's owner-sealed
   * write-body (D-03c issuance write), mirroring the real web client's
   * addRecipientPubkeyPin pin-first share flow (ShareDialog.tsx).
   *
   * Every grant root in this script is a DIRECT child of the vault root, so its
   * write key is derived from the vault root's write key via the grant root's
   * WriteChildRef (D-07 write plane). The pin is what the desktop scope-exit
   * rotation's re-mint (FuseRotationDeps::get_recipient_pubkey_pins ->
   * re_mint_grants_rooted_at, D-03d/D-03e) verifies the retained recipient
   * against BEFORE re-wrapping the rotated read key. A raw `POST /shares`
   * alone (no pin) leaves the grant root pin-less, so the re-mint fails closed
   * ("0 pinned"), aborting the rotation mid-flight and cascading into
   * AES-GCM refresh failures — exactly the D-16 regression this restores.
   *
   * updateFolderMetadataAndPublish runs a CAS-409 loop (maxAttempts 3) that
   * UNIONs recipient pins, so this is race-safe against the mount's concurrent
   * publishing of the same grant root. Pins are public ECIES keys — copied,
   * never rotated.
   */
  const pinRecipientOnGrantRoot = async (
    grantRootRef: SealedChildRef,
    grantRootReadKey: Uint8Array,
    grantRootNodeId: string,
    recipientPublicKey: Uint8Array
  ): Promise<void> => {
    // Vault-root write-body -> the grant root's WriteChildRef (keyed by the
    // child node id, D-07), then derive the grant root's own write key.
    const rootPublished = await fetchPublishedNode(rootIpnsName, ownerCtx);
    const rootNode = await unsealNode(rootPublished, rootReadKey, rootWriteKey);
    const wcr = rootNode.writeBody?.writeChildren.find((w) => w.childId === grantRootNodeId);
    if (!wcr) {
      throw new Error(
        `pinRecipientOnGrantRoot: no WriteChildRef for grant root ${grantRootNodeId} under the vault root`
      );
    }
    const grantRootWriteKey = await unsealChildWriteKey(
      wcr.writeKeySealed,
      rootWriteKey,
      grantRootNodeId,
      'folder',
      grantRootRef.generation
    );

    // Grant root's own write-body -> current pins + writeChildren + signing seed.
    const grantRootPublished = await fetchPublishedNode(grantRootRef.ipnsName, ownerCtx);
    const grantRootNode = await unsealNode(grantRootPublished, grantRootReadKey, grantRootWriteKey);
    if (!grantRootNode.writeBody) {
      throw new Error(
        `pinRecipientOnGrantRoot: grant root ${grantRootRef.ipnsName} has no write-body`
      );
    }
    const nextPins = appendRecipientPin(
      grantRootNode.writeBody.recipientPins ?? [],
      recipientPublicKey
    );
    const resolved = await resolveIpnsRecord(grantRootRef.ipnsName, ownerCtx);
    if (!resolved) {
      throw new Error(
        `pinRecipientOnGrantRoot: grant root ${grantRootRef.ipnsName} did not resolve`
      );
    }
    await updateFolderMetadataAndPublish({
      children: grantRootNode.children ?? [],
      baseChildren: grantRootNode.children ?? [],
      readKey: grantRootReadKey,
      writeKey: grantRootWriteKey,
      writeChildren: grantRootNode.writeBody.writeChildren,
      recipientPins: nextPins,
      ipnsPrivateKey: grantRootNode.writeBody.ipnsPrivateKey,
      ipnsName: grantRootRef.ipnsName,
      sequenceNumber: resolved.sequenceNumber,
      nodeId: grantRootNodeId,
      nodeGeneration: grantRootNode.generation,
      ctx: ownerCtx,
    });
    console.log(
      `  pinned recipient on grant root ${grantRootRef.ipnsName} (${nextPins.length} pin(s) now sealed)`
    );
  };

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

    // Confirm the file landed inside the shared folder before measuring. Nudge the
    // folder each iteration so a FUSE-T-deferred `release` still drains the parent
    // republish (see pollFindChild's nudgePaths doc).
    await pollFindChild(grantRootIpnsName, sharedFolderReadKey, sharedFileName, ownerCtx, [
      join(args.mount, sharedFolderName),
    ]);

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
      encryptedReadKey: bytesToHex(wrappedForBob),
      rootNodeId: grantRootNodeId,
      shareRootIpnsName: grantRootIpnsName,
    });
    const shareId: string = shareRes.data.shareId;
    console.log(`Created share ${shareId} for ${bobEmail} rooted at ${grantRootIpnsName}`);

    // D-03c (Plan 80): pin Bob's pubkey onto the grant root's owner-sealed
    // write-body — the real web share flow does this (pin-first), and the
    // desktop scope-exit re-mint fails closed without it ("0 pinned", D-03e).
    // Done BEFORE the sent_shares wait below so the mount's periodic metadata
    // refresh materializes the pin onto the grant-root inode before the delete.
    await pinRecipientOnGrantRoot(sharedRef, sharedFolderReadKey, grantRootNodeId, bobPublicKey);
    nudge(join(args.mount, sharedFolderName));

    // Bob unwraps his copy of the key WHILE the share is active -- a positive
    // control proving the grant genuinely worked (so "cut off after rotation"
    // isn't just "never worked").
    const receivedRes = await bobCtx.axiosInstance!.get('/shares/received');
    const receivedShare = (
      receivedRes.data.shares as Array<{ shareId: string; encryptedReadKey: string }>
    ).find((s) => s.shareId === shareId);
    if (!receivedShare) {
      throw new Error('Bob does not see the newly created share in /shares/received');
    }
    const bobFolderReadKey = await unwrapKey(
      hexToBytes(receivedShare.encryptedReadKey),
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
    // axiosInstance rejects on non-2xx, so guard the whole call: a failed
    // cleanup revoke must not abort Part B (the rotation already cut Bob off).
    try {
      const revokeRes = await axiosInstance.delete(`/shares/${shareId}`);
      if (revokeRes.status !== 204) {
        console.warn(`Cleanup: revoking share ${shareId} returned ${revokeRes.status} (non-fatal)`);
      }
    } catch (err) {
      console.warn(`Cleanup: revoking share ${shareId} failed (non-fatal): ${String(err)}`);
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

    // Nudge the folder each iteration (same FUSE-T-deferred-release reason as Part A).
    await pollFindChild(privateFolderIpnsName, privateFolderReadKey, privateFileName, ownerCtx, [
      join(args.mount, privateFolderName),
    ]);

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

    // -----------------------------------------------------------------
    // PART C: deep (depth>=2) scope-exit decryptability invariant (SC1)
    // + retained-vs-revoked recipient distinction (SC2).
    //
    // Tree:  DeepGrant-{tag}/            <- grant root (shared to Eve + Carol)
    //          folderB/
    //            fileC.txt               <- covered scope-exit DELETE target
    //            fileSibling.txt         <- retained; proves the File-inode
    //                                        refresh fix (74-03) at depth 2
    //
    // Eve is explicitly REVOKED (DELETE /shares/:shareId) BEFORE the delete
    // fires, so she is a genuinely non-active grantee -- her pre-rotation
    // keys must fail at every depth (folderB AND fileSibling), proving the
    // deep-path intermediate-inode refresh (SC1) closes the bypass Pitfall 3
    // warns against (assert decryptability, never an exact publish count).
    //
    // Carol stays ACTIVE through the delete -- she satisfies the ancestor
    // covering-grant gate (so the delete is genuinely a scope-exit, not
    // private) AND proves the retained-recipient re-mint (SC2,
    // FuseRotationDeps::query_grants_rooted_at/update_grant, 74-05): after
    // rotation she must fetch a NEW encryptedReadKey via /shares/received
    // and still decrypt folderB with it.
    // -----------------------------------------------------------------
    console.log('\n--- Part C: deep scope-exit decryptability + retained-vs-revoked (SC1+SC2) ---');
    const deepGrantFolderName = `DeepGrant-${tag}`;
    const folderBName = 'folderB';
    const fileCName = 'fileC.txt';
    const fileSiblingName = 'fileSibling.txt';

    mkdirSync(join(args.mount, deepGrantFolderName, folderBName), { recursive: true });
    await sleep(3000);
    nudge(args.mount, join(args.mount, deepGrantFolderName));
    writeFileSync(
      join(args.mount, deepGrantFolderName, folderBName, fileCName),
      'deep covered scope-exit target -- must become undecryptable at depth'
    );
    writeFileSync(
      join(args.mount, deepGrantFolderName, folderBName, fileSiblingName),
      'retained sibling file -- must be refreshed to the new key, not left stale'
    );
    await sleep(5000);
    nudge(join(args.mount, deepGrantFolderName, folderBName));

    const deepGrantRef = await pollFindChild(
      rootIpnsName,
      rootReadKey,
      deepGrantFolderName,
      ownerCtx
    );
    const { childReadKey: deepGrantReadKey, childPublished: deepGrantPublished } =
      await deriveChildReadKey(deepGrantRef, rootReadKey, ownerCtx);
    const deepGrantIpnsName = deepGrantRef.ipnsName;
    const deepGrantNodeId = deepGrantPublished.id;

    const folderBRef = await pollFindChild(
      deepGrantIpnsName,
      deepGrantReadKey,
      folderBName,
      ownerCtx,
      [join(args.mount, deepGrantFolderName)]
    );
    const { childReadKey: folderBReadKey } = await deriveChildReadKey(
      folderBRef,
      deepGrantReadKey,
      ownerCtx
    );
    const folderBIpnsName = folderBRef.ipnsName;

    const fileCRef = await pollFindChild(folderBIpnsName, folderBReadKey, fileCName, ownerCtx, [
      join(args.mount, deepGrantFolderName, folderBName),
    ]);
    const fileSiblingRef = await pollFindChild(
      folderBIpnsName,
      folderBReadKey,
      fileSiblingName,
      ownerCtx,
      [join(args.mount, deepGrantFolderName, folderBName)]
    );

    // Grant Eve and Carol read access to the DEEP grant root (matches Part
    // A's "grant must stay active through the delete" discipline for the
    // ancestor covering-grant gate).
    const wrappedForEve = await wrapKey(deepGrantReadKey, eve.publicKey);
    const eveShareRes = await axiosInstance.post('/shares', {
      recipientPublicKey: '0x' + bytesToHex(eve.publicKey),
      encryptedReadKey: bytesToHex(wrappedForEve),
      rootNodeId: deepGrantNodeId,
      shareRootIpnsName: deepGrantIpnsName,
    });
    const eveShareId: string = eveShareRes.data.shareId;

    const wrappedForCarol = await wrapKey(deepGrantReadKey, carol.publicKey);
    const carolShareRes = await axiosInstance.post('/shares', {
      recipientPublicKey: '0x' + bytesToHex(carol.publicKey),
      encryptedReadKey: bytesToHex(wrappedForCarol),
      rootNodeId: deepGrantNodeId,
      shareRootIpnsName: deepGrantIpnsName,
    });
    const carolShareId: string = carolShareRes.data.shareId;
    console.log(
      `Created deep-grant shares ${eveShareId} (Eve, will be revoked) and ${carolShareId} (Carol, retained)`
    );

    // D-03c (Plan 80): pin BOTH recipients onto the deep grant root's write-body
    // (mirrors the web pin-first share flow). Carol is the RETAINED recipient the
    // re-mint must verify against and re-wrap (D-03d); Eve is revoked before the
    // delete so her grant is hard-deleted and never re-minted, but pinning her too
    // matches the web (pin-every-share) and is harmless (a stale pin grants
    // nothing). Without Carol's pin the deep re-mint fails closed ("0 pinned").
    await pinRecipientOnGrantRoot(deepGrantRef, deepGrantReadKey, deepGrantNodeId, eve.publicKey);
    await pinRecipientOnGrantRoot(deepGrantRef, deepGrantReadKey, deepGrantNodeId, carol.publicKey);
    nudge(join(args.mount, deepGrantFolderName));

    // Positive control: BOTH recipients independently derive the grant-root
    // key, then walk it down to folderB, fileC, and fileSibling THEMSELVES --
    // SealedChildRef.readKeySealed is sealed only under the PARENT read key,
    // not per-recipient, so any holder of the parent key derives children
    // the same way an owner would. This proves the deep access chain
    // genuinely worked pre-rotation for both, so a post-rotation failure
    // below proves something.
    const deriveAllDepthsFor = async (
      recipientCtx: SdkContext,
      recipientPrivateKey: Uint8Array,
      encryptedReadKeyHex: string
    ): Promise<{
      grantRootKey: Uint8Array;
      folderBKey: Uint8Array;
      fileCKey: Uint8Array;
      fileSiblingKey: Uint8Array;
    }> => {
      const grantRootKey = await unwrapKey(hexToBytes(encryptedReadKeyHex), recipientPrivateKey);
      const { childReadKey: folderBKey } = await deriveChildReadKey(
        folderBRef,
        grantRootKey,
        recipientCtx
      );
      const { childReadKey: fileCKey } = await deriveChildReadKey(
        fileCRef,
        folderBKey,
        recipientCtx
      );
      const { childReadKey: fileSiblingKey } = await deriveChildReadKey(
        fileSiblingRef,
        folderBKey,
        recipientCtx
      );
      return { grantRootKey, folderBKey, fileCKey, fileSiblingKey };
    };

    const eveReceivedRes = await eve.ctx.axiosInstance!.get('/shares/received');
    const eveReceivedShare = (
      eveReceivedRes.data.shares as Array<{ shareId: string; encryptedReadKey: string }>
    ).find((s) => s.shareId === eveShareId);
    if (!eveReceivedShare) {
      throw new Error('Eve does not see the newly created deep-grant share in /shares/received');
    }
    const eveKeys = await deriveAllDepthsFor(
      eve.ctx,
      eve.privateKey,
      eveReceivedShare.encryptedReadKey
    );

    const carolReceivedRes = await carol.ctx.axiosInstance!.get('/shares/received');
    const carolReceivedShare = (
      carolReceivedRes.data.shares as Array<{ shareId: string; encryptedReadKey: string }>
    ).find((s) => s.shareId === carolShareId);
    if (!carolReceivedShare) {
      throw new Error('Carol does not see the newly created deep-grant share in /shares/received');
    }
    const carolKeys = await deriveAllDepthsFor(
      carol.ctx,
      carol.privateKey,
      carolReceivedShare.encryptedReadKey
    );

    const eveDeepPreCheck =
      (await canRead(folderBIpnsName, eveKeys.folderBKey, eve.ctx)) &&
      (await canReadFile(fileCRef.ipnsName, eveKeys.fileCKey, eve.ctx)) &&
      (await canReadFile(fileSiblingRef.ipnsName, eveKeys.fileSiblingKey, eve.ctx));
    const carolDeepPreCheck =
      (await canRead(folderBIpnsName, carolKeys.folderBKey, carol.ctx)) &&
      (await canReadFile(fileCRef.ipnsName, carolKeys.fileCKey, carol.ctx)) &&
      (await canReadFile(fileSiblingRef.ipnsName, carolKeys.fileSiblingKey, carol.ctx));
    if (!eveDeepPreCheck || !carolDeepPreCheck) {
      throw new Error(
        'PRECONDITION FAILED: Eve and/or Carol could not decrypt folderB/fileC/fileSibling while the ' +
          'deep grant was ACTIVE -- the grant never worked at depth, so a post-rotation failure below ' +
          'would prove nothing'
      );
    }
    console.log(
      'PASS: Eve and Carol could both decrypt folderB, fileC, and fileSibling while the deep grant ' +
        'was active (positive control at every depth)'
    );

    // Wait for the mount's sent_shares cache to observe BOTH active grants.
    await sleep(35000);

    // Explicitly revoke Eve's grant BEFORE the delete -- she must be a
    // genuinely non-active grantee for the "revoked recipient" half of this
    // leg. Carol's grant stays active so the ancestor covering-grant gate
    // still treats the delete as a scope-exit (not private).
    const eveRevokeRes = await axiosInstance.delete(`/shares/${eveShareId}`);
    if (eveRevokeRes.status !== 204) {
      throw new Error(
        `Revoking Eve's deep-grant share returned ${eveRevokeRes.status}, expected 204`
      );
    }
    console.log(`Revoked Eve's share ${eveShareId} -- she is now a non-active grantee`);
    // Give the periodic sent_shares refresh a moment to observe the revoke
    // too (best-effort; the gate only needs Carol's grant to stay covered).
    await sleep(5000);

    const seqFolderBBeforeDelete = await resolveIpnsRecord(folderBIpnsName, ownerCtx).then((r) => {
      if (!r) throw new Error(`folderB ${folderBIpnsName} did not resolve before the deep delete`);
      return r.sequenceNumber;
    });

    let deepDeleteSucceeded = false;
    let lastDeepDeleteError: unknown;
    for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
      try {
        rmSync(join(args.mount, deepGrantFolderName, folderBName, fileCName));
        deepDeleteSucceeded = true;
        break;
      } catch (err) {
        lastDeepDeleteError = err;
        nudge(join(args.mount, deepGrantFolderName, folderBName));
        await sleep(RETRY_DELAY_MS);
      }
    }

    if (!deepDeleteSucceeded) {
      console.error(
        `FAIL: deep covered scope-exit delete of ${fileCName} did not succeed after ${ATTEMPTS} ` +
          `attempts. Last error: ${String(lastDeepDeleteError)}`
      );
      failed = true;
    } else {
      console.log('PASS: deep covered scope-exit delete completed with no EIO');

      // Readiness gate only -- per Pitfall 3, do NOT assert an exact sequence
      // delta for the deep case (coalescing behaves differently one level
      // down); just wait until folderB's own key has genuinely rotated.
      await pollSequenceBump(folderBIpnsName, seqFolderBBeforeDelete, ownerCtx);

      // SECURITY INVARIANT (SC1): Eve's PRE-rotation keys can no longer
      // decrypt ANY node under the grant root, at ANY depth -- folderB (the
      // intermediate node 74-03 fixes) AND fileSibling (the retained File
      // 74-03's InodeKind::File arm fixes). This is the deep-path bypass
      // class: before 74-03, only the grant-root's own inode was refreshed,
      // so folderB's stale key would have kept decrypting here.
      const eveFolderBAfter = await canRead(folderBIpnsName, eveKeys.folderBKey, eve.ctx);
      const eveFileSiblingAfter = await canReadFile(
        fileSiblingRef.ipnsName,
        eveKeys.fileSiblingKey,
        eve.ctx
      );
      if (!eveFolderBAfter && !eveFileSiblingAfter) {
        console.log(
          'PASS: revoked recipient (Eve) cannot decrypt folderB NOR fileSibling with her pre-rotation ' +
            'keys -- the deep intermediate-inode refresh closed the bypass at every depth'
        );
      } else {
        console.error(
          `FAIL: revoked recipient (Eve) can STILL decrypt ${eveFolderBAfter ? 'folderB' : ''}` +
            `${eveFolderBAfter && eveFileSiblingAfter ? ' AND ' : ''}${eveFileSiblingAfter ? 'fileSibling' : ''} ` +
            'with her pre-rotation key(s) -- deep-path revocation bypass regressed (SC1)'
        );
        failed = true;
      }

      // fileC itself was the delete TARGET, not a retained node -- its own
      // key is not re-minted by the walk (nothing to walk into once it's
      // gone). The meaningful guarantee is that Eve cannot reach it via a
      // FRESH derivation any more (folderB's key rotated, above). We still
      // probe her PRE-captured fileC key directly against fileC's own IPNS
      // name as a belt-and-suspenders check; a throw here is a bonus PASS,
      // but this alone is NOT the primary SC1 gate -- once a key is derived
      // and content is content-addressed on IPFS, that specific historical
      // secret is not retroactively re-protected by a later rotation this
      // key was never part of; this is a documented forward-secrecy
      // boundary, not a regression of this phase's fix.
      const eveFileCStaleKeyStillResolves = await canReadFile(
        fileCRef.ipnsName,
        eveKeys.fileCKey,
        eve.ctx
      );
      console.log(
        eveFileCStaleKeyStillResolves
          ? "INFO: fileC (the delete target) is still independently resolvable via Eve's pre-captured " +
              'key -- expected forward-secrecy boundary for an already-derived leaf key, not the SC1 gate'
          : "PASS (bonus): fileC's own IPNS record is also no longer resolvable with Eve's pre-rotation key"
      );

      // SECURITY INVARIANT (SC2): Carol -- who was NEVER revoked -- must
      // RETAIN read access. Poll /shares/received for her RE-MINTED
      // encryptedReadKey (proves FuseRotationDeps::update_grant genuinely
      // fired via query_grants_rooted_at, 74-05), then confirm the new key
      // decrypts folderB's freshly-rotated record.
      const carolRemint = await pollGrantRemint(
        carol.ctx,
        carolShareId,
        carolReceivedShare.encryptedReadKey
      );
      const carolNewGrantRootKey = await unwrapKey(
        hexToBytes(carolRemint.encryptedReadKey),
        carol.privateKey
      );
      // Reload folderB's CURRENT SealedChildRef from the grant root under the
      // NEW grant-root key: the pre-rotation `folderBRef.readKeySealed` was
      // sealed under Carol's OLD grant-root key, but the scope-exit rotation
      // re-sealed folderB under the NEW grant-root key and republished. Deriving
      // from the stale ref would fail to unwrap; mirror the reload pattern used
      // elsewhere in this file so SC2 genuinely proves retained-vs-revoked.
      const refreshedFolderBRef = await pollFindChild(
        deepGrantIpnsName,
        carolNewGrantRootKey,
        folderBName,
        carol.ctx
      );
      const { childReadKey: carolNewFolderBKey } = await deriveChildReadKey(
        refreshedFolderBRef,
        carolNewGrantRootKey,
        carol.ctx
      );
      const carolRetainedAccess = await canRead(folderBIpnsName, carolNewFolderBKey, carol.ctx);
      if (carolRetainedAccess) {
        console.log(
          'PASS: retained recipient (Carol) was re-minted to the new generation and still decrypts ' +
            'folderB -- retained-vs-revoked distinction holds (SC2, over-broad-revocation regression guarded)'
        );
      } else {
        console.error(
          "FAIL: retained recipient (Carol)'s re-minted key does NOT decrypt folderB -- over-broad " +
            'revocation regressed (a retained recipient was wrongly cut, SC2)'
        );
        failed = true;
      }
      clearBytes(carolNewGrantRootKey);
      clearBytes(carolNewFolderBKey);
    }

    // Cleanup: revoke Carol's now-stale share (Eve's was already revoked above).
    try {
      const carolRevokeRes = await axiosInstance.delete(`/shares/${carolShareId}`);
      if (carolRevokeRes.status !== 204) {
        console.warn(
          `Cleanup: revoking share ${carolShareId} returned ${carolRevokeRes.status} (non-fatal)`
        );
      }
    } catch (err) {
      console.warn(`Cleanup: revoking share ${carolShareId} failed (non-fatal): ${String(err)}`);
    }

    clearBytes(deepGrantReadKey);
    clearBytes(folderBReadKey);
    clearBytes(eveKeys.grantRootKey);
    clearBytes(eveKeys.folderBKey);
    clearBytes(eveKeys.fileCKey);
    clearBytes(eveKeys.fileSiblingKey);
    clearBytes(carolKeys.grantRootKey);
    clearBytes(carolKeys.folderBKey);
    clearBytes(carolKeys.fileCKey);
    clearBytes(carolKeys.fileSiblingKey);

    // -----------------------------------------------------------------
    // PART D: overwrite-rename against a covered destination (SC3).
    //
    // Exercises the destination scope-exit gate added to WinFsp's
    // handle_rename in 74-06 (crates/fuse/src/platform/windows/write_ops.rs)
    // -- the runtime counterpart to that plan's unit tests
    // (rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit).
    // On fuser (macOS/Linux) this exercises the ALREADY-correct D-15d dest
    // gate (crates/fuse/src/write_ops/implementation/rename.rs) -- a
    // regression guard there, not new coverage -- but is kept in the SAME
    // script/step so the leg runs on all 3 platforms via run-all.sh/
    // run-all.ps1 without introducing a second script file (RESEARCH A3:
    // extend, don't duplicate).
    //
    // Tree: RenameOverwrite-{tag}/  <- grant root (shared to Frank + Grace)
    //         destFile.txt          <- overwrite TARGET (removed by the rename)
    //         sourceFile.txt        <- rename SOURCE, renamed ONTO destFile.txt
    //
    // Frank is explicitly revoked before the rename; Grace stays active
    // (satisfies the covering-grant gate + proves retained access survives a
    // dest-gate-triggered rotation, not just a delete-triggered one).
    // -----------------------------------------------------------------
    console.log('\n--- Part D: overwrite-rename against a covered destination (SC3) ---');
    const renameFolderName = `RenameOverwrite-${tag}`;
    const destFileName = 'destFile.txt';
    const sourceFileName = 'sourceFile.txt';

    mkdirSync(join(args.mount, renameFolderName), { recursive: true });
    await sleep(3000);
    nudge(args.mount);
    writeFileSync(
      join(args.mount, renameFolderName, destFileName),
      'destination content -- will be overwritten and its covering grant must rotate'
    );
    writeFileSync(
      join(args.mount, renameFolderName, sourceFileName),
      'source content that must survive the overwrite-rename'
    );
    await sleep(5000);
    nudge(join(args.mount, renameFolderName));

    const renameFolderRef = await pollFindChild(
      rootIpnsName,
      rootReadKey,
      renameFolderName,
      ownerCtx
    );
    const { childReadKey: renameFolderReadKey, childPublished: renameFolderPublished } =
      await deriveChildReadKey(renameFolderRef, rootReadKey, ownerCtx);
    const renameFolderIpnsName = renameFolderRef.ipnsName;
    const renameFolderNodeId = renameFolderPublished.id;

    await pollFindChild(renameFolderIpnsName, renameFolderReadKey, destFileName, ownerCtx, [
      join(args.mount, renameFolderName),
    ]);
    await pollFindChild(renameFolderIpnsName, renameFolderReadKey, sourceFileName, ownerCtx, [
      join(args.mount, renameFolderName),
    ]);

    const wrappedForFrank = await wrapKey(renameFolderReadKey, frank.publicKey);
    const frankShareRes = await axiosInstance.post('/shares', {
      recipientPublicKey: '0x' + bytesToHex(frank.publicKey),
      encryptedReadKey: bytesToHex(wrappedForFrank),
      rootNodeId: renameFolderNodeId,
      shareRootIpnsName: renameFolderIpnsName,
    });
    const frankShareId: string = frankShareRes.data.shareId;

    const wrappedForGrace = await wrapKey(renameFolderReadKey, grace.publicKey);
    const graceShareRes = await axiosInstance.post('/shares', {
      recipientPublicKey: '0x' + bytesToHex(grace.publicKey),
      encryptedReadKey: bytesToHex(wrappedForGrace),
      rootNodeId: renameFolderNodeId,
      shareRootIpnsName: renameFolderIpnsName,
    });
    const graceShareId: string = graceShareRes.data.shareId;
    console.log(
      `Created rename-overwrite shares ${frankShareId} (Frank, will be revoked) and ${graceShareId} (Grace, retained)`
    );

    // D-03c (Plan 80): pin both recipients onto the rename-overwrite grant root's
    // write-body. Grace is the RETAINED recipient the re-mint re-wraps (D-03d);
    // Frank is revoked before the rename so he is never re-minted. Without
    // Grace's pin the re-mint fails closed ("0 pinned"), aborting the covered
    // overwrite-rename's scope-exit rotation.
    await pinRecipientOnGrantRoot(
      renameFolderRef,
      renameFolderReadKey,
      renameFolderNodeId,
      frank.publicKey
    );
    await pinRecipientOnGrantRoot(
      renameFolderRef,
      renameFolderReadKey,
      renameFolderNodeId,
      grace.publicKey
    );
    nudge(join(args.mount, renameFolderName));

    const frankReceivedRes = await frank.ctx.axiosInstance!.get('/shares/received');
    const frankReceivedShare = (
      frankReceivedRes.data.shares as Array<{ shareId: string; encryptedReadKey: string }>
    ).find((s) => s.shareId === frankShareId);
    if (!frankReceivedShare) {
      throw new Error(
        'Frank does not see the newly created rename-overwrite share in /shares/received'
      );
    }
    const frankPreRotationKey = await unwrapKey(
      hexToBytes(frankReceivedShare.encryptedReadKey),
      frank.privateKey
    );

    const graceReceivedRes = await grace.ctx.axiosInstance!.get('/shares/received');
    const graceReceivedShare = (
      graceReceivedRes.data.shares as Array<{ shareId: string; encryptedReadKey: string }>
    ).find((s) => s.shareId === graceShareId);
    if (!graceReceivedShare) {
      throw new Error(
        'Grace does not see the newly created rename-overwrite share in /shares/received'
      );
    }

    const frankPreCheck = await canRead(renameFolderIpnsName, frankPreRotationKey, frank.ctx);
    if (!frankPreCheck) {
      throw new Error(
        'PRECONDITION FAILED: Frank could not decrypt the rename-overwrite folder while the share was ' +
          'ACTIVE -- the share never worked, so a post-rename failure below would prove nothing'
      );
    }
    console.log('PASS: Frank could decrypt the rename-overwrite folder while the grant was active');

    await sleep(35000);

    const frankRenameRevokeRes = await axiosInstance.delete(`/shares/${frankShareId}`);
    if (frankRenameRevokeRes.status !== 204) {
      throw new Error(
        `Revoking Frank's rename-overwrite share returned ${frankRenameRevokeRes.status}, expected 204`
      );
    }
    console.log(`Revoked Frank's share ${frankShareId} -- he is now a non-active grantee`);
    await sleep(5000);

    const seqRenameFolderBeforeRename = await resolveIpnsRecord(
      renameFolderIpnsName,
      ownerCtx
    ).then((r) => {
      if (!r)
        throw new Error(`${renameFolderIpnsName} did not resolve before the overwrite-rename`);
      return r.sequenceNumber;
    });

    // Overwrite-rename THROUGH THE MOUNT: sourceFile.txt replaces
    // destFile.txt. Node's renameSync overwrites an existing destination on
    // both POSIX (fuser) and Windows (WinFsp handles this with
    // replace_if_exists=true, matching MoveFileExW's MOVEFILE_REPLACE_EXISTING
    // that Node's uv_fs_rename sets internally on win32).
    let renameSucceeded = false;
    let lastRenameError: unknown;
    for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
      try {
        renameSync(
          join(args.mount, renameFolderName, sourceFileName),
          join(args.mount, renameFolderName, destFileName)
        );
        renameSucceeded = true;
        break;
      } catch (err) {
        lastRenameError = err;
        nudge(join(args.mount, renameFolderName));
        await sleep(RETRY_DELAY_MS);
      }
    }

    if (!renameSucceeded) {
      console.error(
        `FAIL: overwrite-rename of ${sourceFileName} onto ${destFileName} did not succeed after ` +
          `${ATTEMPTS} attempts. Last error: ${String(lastRenameError)}\n` +
          '  A PERSISTENT failure here means either the dest-gate is rejecting a legitimate overwrite ' +
          '(regression) or the sent_shares cache is not authoritative -- see the script header.'
      );
      failed = true;
    } else {
      console.log('PASS: overwrite-rename completed with no error');

      await pollSequenceBump(renameFolderIpnsName, seqRenameFolderBeforeRename, ownerCtx);

      // SECURITY INVARIANT (SC3): the dest-gate rotated the covering grant on
      // overwrite -- Frank (revoked pre-rename) can no longer decrypt the
      // folder with his pre-rotation key. Before 74-06, WinFsp's
      // handle_rename never gated dest_ino at all, so this would have stayed
      // readable (bypass); fuser already gated correctly (regression guard
      // here).
      const frankAfterRename = await canRead(renameFolderIpnsName, frankPreRotationKey, frank.ctx);
      if (!frankAfterRename) {
        console.log(
          'PASS: revoked recipient (Frank) can no longer decrypt the rename-overwrite folder -- the ' +
            'destination scope-exit gate rotated on overwrite (SC3)'
        );
      } else {
        console.error(
          'FAIL: revoked recipient (Frank) can STILL decrypt the rename-overwrite folder -- the ' +
            'destination scope-exit gate did not rotate on overwrite (SC3 bypass)'
        );
        failed = true;
      }

      // Retained recipient (Grace) keeps access via the same re-mint seam.
      const graceRemint = await pollGrantRemint(
        grace.ctx,
        graceShareId,
        graceReceivedShare.encryptedReadKey
      );
      const graceNewKey = await unwrapKey(
        hexToBytes(graceRemint.encryptedReadKey),
        grace.privateKey
      );
      const graceRetainedAccess = await canRead(renameFolderIpnsName, graceNewKey, grace.ctx);
      if (graceRetainedAccess) {
        console.log(
          'PASS: retained recipient (Grace) was re-minted and still decrypts the rename-overwrite ' +
            'folder -- retained-vs-revoked distinction holds on the rename path too'
        );
      } else {
        console.error(
          "FAIL: retained recipient (Grace)'s re-minted key does NOT decrypt the rename-overwrite folder"
        );
        failed = true;
      }
      clearBytes(graceNewKey);
    }

    try {
      const graceRevokeRes = await axiosInstance.delete(`/shares/${graceShareId}`);
      if (graceRevokeRes.status !== 204) {
        console.warn(
          `Cleanup: revoking share ${graceShareId} returned ${graceRevokeRes.status} (non-fatal)`
        );
      }
    } catch (err) {
      console.warn(`Cleanup: revoking share ${graceShareId} failed (non-fatal): ${String(err)}`);
    }

    clearBytes(renameFolderReadKey);
    clearBytes(frankPreRotationKey);
  } finally {
    clearBytes(rootReadKey);
    clearBytes(rootWriteKey);
    clearBytes(ownerPrivateKey);
    clearBytes(bobPrivateKey);
    clearBytes(eve.privateKey);
    clearBytes(carol.privateKey);
    clearBytes(frank.privateKey);
    clearBytes(grace.privateKey);
  }

  console.log(`\n=== Shared scope-exit rotation acceptance: ${failed ? 'FAILED' : 'PASSED'} ===`);
  process.exit(failed ? 1 : 0);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
