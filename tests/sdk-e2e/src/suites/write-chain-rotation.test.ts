/**
 * Write-chain rotation suite (D-04 phase gate) — Phase 65.
 *
 * Proves write-revocation end-to-end against the live docker API stack
 * (mirrors Phase-64 TEST-01 for the read plane). Two sequential tests:
 *
 *   1. Build a 2-level write-capable subtree (share root → child folder) with
 *      real write-bodies, first-publish each at sequenceNumber 1n, and assert
 *      the pre-rotation baseline: write-body unseals under writeKey; parent
 *      write link unseals to child writeKey.
 *
 *   2. Drive rotateWriteFromNode with injected vi.fn() callbacks, assert:
 *      - WRITE-02: each node gets a new k51 name (!= old); parent re-point
 *        cascade (root's SealedChildRef.ipnsName → new child name).
 *      - WRITE-04: teeUnenrollFn fired for each old name (tombstone-intent).
 *      - WRITE-03: surviving co-writer (bob) gets wrapKey re-wrap via
 *        encryptedWriteKeyPersistFn; revoked recipient is dropped via
 *        deleteWriteGrantFn.
 *      - Read-plane invariance: generation unchanged, readKey not rotated.
 *
 * D-02 scope: live publish-gate reject / resolve-410 / encryptedWriteKey
 * persistence are behind injected callbacks (Phase 66 enforces live).
 * The round-trip itself (IPFS pin + IPNS publish/resolve) is real.
 *
 * Prerequisites (live local stack):
 *   docker compose -f docker/docker-compose.yml up -d   (redis 6380, kubo, postgres)
 *   pnpm --filter @cipherbox/api dev                    (API on :3000)
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  addToIpfs,
  createAndPublishIpnsRecord,
  fetchFromIpfs,
  resolveIpnsRecord,
  rotateWriteFromNode,
  type SdkContext,
  type WriteRevocationCallbacks,
} from '@cipherbox/sdk-core';
import {
  sealChildReadKey,
  sealChildWriteKey,
  sealNode,
  unsealChildWriteKey,
  unsealNode,
} from '@cipherbox/core';
import type { Node, PublishedNode } from '@cipherbox/core';
import {
  deriveEd25519PublicKey,
  deriveIpnsName,
  generateEd25519Keypair,
  generateRandomBytes,
  unwrapKey,
} from '@cipherbox/crypto';
import { type MultiAccountFixture, createMultiAccountFixture } from '../fixtures/multi-account';

// ---------------------------------------------------------------------------
// Shared fixture and spy
// ---------------------------------------------------------------------------

let fixture: MultiAccountFixture;

/**
 * 32-byte values captured from crypto.getRandomValues during write-rotation.
 *
 * rotateWriteSubtree calls generateEd25519Keypair() then generateRandomBytes(32)
 * per node (child-first order). For a 2-node tree (child, then root):
 *   [0] = new child Ed25519 seed
 *   [1] = new child write key
 *   [2] = new root Ed25519 seed
 *   [3] = new root write key
 *
 * AES-GCM IVs (12 bytes) are filtered out by the 32-byte guard below.
 * Reset via clearCapturedKeys() immediately before each rotateWriteFromNode call.
 */
const capturedKeys: Uint8Array[] = [];

function clearCapturedKeys(): void {
  for (const key of capturedKeys) {
    key.fill(0);
  }
  capturedKeys.length = 0;
}

beforeAll(async () => {
  fixture = await createMultiAccountFixture(['alice', 'bob']);

  // Install spy once for the whole suite. The original is called first so
  // all callers receive real random bytes; we only intercept 32-byte calls.
  const origGetRV = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
  vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (array: any) => {
      origGetRV(array as ArrayBufferView);
      if (array instanceof Uint8Array && array.length === 32) {
        capturedKeys.push(new Uint8Array(array));
      }
      return array;
    }
  );
});

afterAll(async () => {
  clearCapturedKeys();
  vi.restoreAllMocks();
  if (fixture) await fixture.cleanupAll();
});

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Resolve IPNS and return the plaintext PublishedNode envelope. */
async function fetchPublishedEnvelope(ipnsName: string, ctx: SdkContext): Promise<PublishedNode> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) throw new Error(`fetchPublishedEnvelope: IPNS not found: ${ipnsName}`);
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}

/**
 * Seal a folder node with a real write-body, upload to IPFS, first-publish
 * to a fresh IPNS keypair (sequenceNumber 1n).
 *
 * The newly minted Ed25519 keypair is set as writeBody.ipnsPrivateKey.
 * Any writeChildren supplied via node.writeBody are preserved.
 * writeKey MUST be a real 32-byte key (not the all-zero dummy).
 */
async function publishWriteCapableNode(
  node: Node,
  readKey: Uint8Array,
  writeKey: Uint8Array,
  ctx: SdkContext
): Promise<{ ipnsName: string }> {
  const keypair = generateEd25519Keypair(); // synchronous
  const ipnsName = await deriveIpnsName(keypair.publicKey);
  const nodeWithWriteBody: Node = {
    ...node,
    writeBody: {
      ipnsPrivateKey: keypair.privateKey,
      writeChildren: node.writeBody?.writeChildren ?? [],
    },
  };
  const pub = await sealNode(nodeWithWriteBody, readKey, writeKey);
  const { cid } = await addToIpfs(ctx, new TextEncoder().encode(JSON.stringify(pub)));
  try {
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: keypair.privateKey,
      ipnsPublicKey: keypair.publicKey,
      ipnsName,
      metadataCid: cid,
      sequenceNumber: 1n, // MUST be 1n — strict gate rejects any other value for new names
      ctx,
    });
  } finally {
    // Zero the plaintext Ed25519 seed immediately after publish — callers only need
    // the ipnsName, not the raw private key material (#20 / D-09 terminal-owner rule).
    keypair.privateKey.fill(0);
  }
  return { ipnsName };
}

// ---------------------------------------------------------------------------
// Suite: D-04 write-chain rotation gate
// ---------------------------------------------------------------------------

describe('Write-chain rotation suite (D-04 phase gate)', () => {
  // Shared state between the two sequential tests.
  let rootIpnsName: string;
  let childIpnsName: string;
  let rootReadKey: Uint8Array;
  let childReadKey: Uint8Array;
  let rootWriteKey: Uint8Array;
  let childWriteKey: Uint8Array;
  let rootNodeId: string;
  let childNodeId: string;

  // ---------------------------------------------------------------------------
  // Test 1: Build the write-capable subtree and verify pre-rotation baseline
  // ---------------------------------------------------------------------------

  it('builds a 2-level write-capable subtree and asserts pre-rotation baseline', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    // Generate independent read and write keys for each node.
    rootReadKey = generateRandomBytes(32);
    rootWriteKey = generateRandomBytes(32);
    childReadKey = generateRandomBytes(32);
    childWriteKey = generateRandomBytes(32);

    rootNodeId = crypto.randomUUID();
    childNodeId = crypto.randomUUID();

    // Seal the child's readKey and writeKey under the root's keys so the root
    // carries the links in its SealedChildRef (read-body) and WriteChildRef (write-body).
    const childReadKeySealed = await sealChildReadKey(
      childReadKey,
      rootReadKey,
      childNodeId,
      'folder',
      0
    );
    const childWriteKeySealed = await sealChildWriteKey(
      childWriteKey,
      rootWriteKey,
      childNodeId,
      'folder',
      0
    );

    // Build and publish the child folder (leaf — no writeChildren).
    const childNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: childNodeId,
      generation: 0,
      createdAt: Date.now(),
      modifiedAt: Date.now(),
      children: [],
      writeBody: { ipnsPrivateKey: new Uint8Array(32), writeChildren: [] },
    };
    ({ ipnsName: childIpnsName } = await publishWriteCapableNode(
      childNode,
      childReadKey,
      childWriteKey,
      aliceCtx
    ));

    // Build and publish the share root folder. Its read-body points at the child
    // via SealedChildRef; its write-body points at the child via WriteChildRef.
    const rootNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: rootNodeId,
      generation: 0,
      createdAt: Date.now(),
      modifiedAt: Date.now(),
      children: [
        {
          name: 'child-folder',
          ipnsName: childIpnsName,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: childReadKeySealed,
        },
      ],
      writeBody: {
        ipnsPrivateKey: new Uint8Array(32), // replaced by publishWriteCapableNode
        writeChildren: [{ childId: childNodeId, writeKeySealed: childWriteKeySealed }],
      },
    };
    ({ ipnsName: rootIpnsName } = await publishWriteCapableNode(
      rootNode,
      rootReadKey,
      rootWriteKey,
      aliceCtx
    ));

    // --- Pre-rotation assertions ---

    // Both nodes resolve and have generation 0.
    const rootPub = await fetchPublishedEnvelope(rootIpnsName, aliceCtx);
    const childPub = await fetchPublishedEnvelope(childIpnsName, aliceCtx);
    expect(rootPub.generation).toBe(0);
    expect(childPub.generation).toBe(0);

    // Read-body unseals under readKey: root's children contains the child's IPNS name.
    const rootNode2 = await unsealNode(rootPub, rootReadKey);
    expect(rootNode2.id).toBe(rootNodeId);
    expect(rootNode2.children?.length).toBe(1);
    expect(rootNode2.children![0].ipnsName).toBe(childIpnsName);

    // Write-body unseals under writeKey: ipnsPrivateKey is present and 32 bytes.
    const rootNodeWithWrite = await unsealNode(rootPub, rootReadKey, rootWriteKey);
    expect(rootNodeWithWrite.writeBody).toBeDefined();
    expect(rootNodeWithWrite.writeBody!.ipnsPrivateKey).toBeInstanceOf(Uint8Array);
    expect(rootNodeWithWrite.writeBody!.ipnsPrivateKey.length).toBe(32);

    // Parent write link unseals to the child's actual writeKey.
    const childWriteKeySealedInRoot = rootNodeWithWrite.writeBody!.writeChildren[0].writeKeySealed;
    const recoveredChildWriteKey = await unsealChildWriteKey(
      childWriteKeySealedInRoot,
      rootWriteKey,
      childNodeId,
      'folder',
      0
    );
    expect(recoveredChildWriteKey).toEqual(childWriteKey);
    recoveredChildWriteKey.fill(0); // zero derived key (terminal owner)

    // Child write-body also unseals correctly under its own writeKey.
    const childNodeWithWrite = await unsealNode(childPub, childReadKey, childWriteKey);
    expect(childNodeWithWrite.writeBody).toBeDefined();
    expect(childNodeWithWrite.writeBody!.ipnsPrivateKey).toBeInstanceOf(Uint8Array);
    expect(childNodeWithWrite.writeBody!.ipnsPrivateKey.length).toBe(32);
  }, 120_000);

  // ---------------------------------------------------------------------------
  // Test 2: rotateWriteFromNode — assert WRITE-02/03/04 end-to-end
  // ---------------------------------------------------------------------------

  it('rotateWriteFromNode — new k51 names, parent re-point, tombstone-intent, co-writer re-wrap', async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;
    const aliceCtx = alice.client.getContext();

    // Capture pre-rotation IPNS names so we can assert they changed.
    const oldRootIpnsName = rootIpnsName;
    const oldChildIpnsName = childIpnsName;

    // Build injected vi.fn() callbacks (D-02: transport seam — Phase 66 wires live).
    const SURVIVOR_SHARE_ID = 'share-survivor-write-0000-0000-0000-000000000001';
    const REVOKED_SHARE_ID = 'share-revoked-write-0000-0000-0000-0000000000ff';
    // Use a distinct non-zero public key for the revoked recipient (uncompressed secp256k1).
    const revokedPubKey = new Uint8Array(65);
    revokedPubKey[0] = 0x04;
    revokedPubKey.fill(0x03, 1);

    const queryWriteGrantsFn = vi.fn().mockResolvedValue([
      { shareId: SURVIVOR_SHARE_ID, recipientPublicKey: bob.publicKey, isRevoked: false },
      { shareId: REVOKED_SHARE_ID, recipientPublicKey: revokedPubKey, isRevoked: true },
    ]);
    const encryptedWriteKeyPersistFn = vi.fn().mockResolvedValue(undefined);
    const teeUnenrollFn = vi.fn().mockResolvedValue(undefined);
    const deleteWriteGrantFn = vi.fn().mockResolvedValue(undefined);

    const callbacks: WriteRevocationCallbacks = {
      queryWriteGrantsFn,
      encryptedWriteKeyPersistFn,
      teeUnenrollFn,
      deleteWriteGrantFn,
    };

    // Clear the spy before rotation so indices are stable (child-first: [0]=child-ed25519
    // seed, [1]=child-writeKey, [2]=root-ed25519 seed, [3]=root-writeKey).
    clearCapturedKeys();

    // --- Run write-chain rotation (live IPFS + IPNS round-trip) ---
    await rotateWriteFromNode({
      rootNodeId,
      rootIpnsName,
      rootReadKey,
      rootWriteKey,
      ctx: aliceCtx,
      callbacks,
    });

    // Derive new IPNS names from the captured Ed25519 seeds.
    // Child is processed first (child-first / bottom-up): index 0 = child seed.
    // Root is processed after: index 2 = root seed.
    expect(capturedKeys.length).toBeGreaterThanOrEqual(4);
    const newChildIpnsPublicKey = deriveEd25519PublicKey(capturedKeys[0]);
    const newChildIpnsName = await deriveIpnsName(newChildIpnsPublicKey);
    const newRootIpnsPublicKey = deriveEd25519PublicKey(capturedKeys[2]);
    const newRootIpnsName = await deriveIpnsName(newRootIpnsPublicKey);
    // Zero the captured seeds immediately after derivation — they are Ed25519 private key
    // material and must not linger in capturedKeys until afterAll (D-09 terminal ownership).
    clearCapturedKeys();

    // -----------------------------------------------------------------------
    // WRITE-02: Each node gets a new k51 name; parent re-points to new child name.
    // -----------------------------------------------------------------------

    // New names must differ from the old names.
    expect(newChildIpnsName).not.toBe(oldChildIpnsName);
    expect(newRootIpnsName).not.toBe(oldRootIpnsName);

    // Both new names must resolve (first-published at seq 1n).
    const newRootPub = await fetchPublishedEnvelope(newRootIpnsName, aliceCtx);
    const newChildPub = await fetchPublishedEnvelope(newChildIpnsName, aliceCtx);
    expect(newRootPub).toBeDefined();
    expect(newChildPub).toBeDefined();

    // Parent re-point: the new root's read-body must point at the NEW child name.
    // readKey is unchanged (write-rotation does not bump readKey — D-06 / ADR 0001).
    const newRootNode = await unsealNode(newRootPub, rootReadKey);
    expect(newRootNode.children?.length).toBe(1);
    expect(newRootNode.children![0].ipnsName).toBe(newChildIpnsName);

    // -----------------------------------------------------------------------
    // WRITE-04: Tombstone-intent — teeUnenrollFn fired for each old name.
    // -----------------------------------------------------------------------

    expect(teeUnenrollFn).toHaveBeenCalledTimes(2);
    const teeCalledNames = teeUnenrollFn.mock.calls.map((c: unknown[]) => c[0] as string);
    expect(teeCalledNames).toContain(oldChildIpnsName);
    expect(teeCalledNames).toContain(oldRootIpnsName);

    // -----------------------------------------------------------------------
    // WRITE-03: Co-writer re-wrap (survivor) + revoked drop.
    // -----------------------------------------------------------------------

    // queryWriteGrantsFn is called once with the root node ID.
    expect(queryWriteGrantsFn).toHaveBeenCalledWith(rootNodeId);

    // Survivor (bob): encryptedWriteKeyPersistFn receives a base64-wrapped new write key.
    expect(encryptedWriteKeyPersistFn).toHaveBeenCalledTimes(1);
    const [persistedShareId, encryptedWriteKey] = encryptedWriteKeyPersistFn.mock.calls[0] as [
      string,
      string,
    ];
    expect(persistedShareId).toBe(SURVIVOR_SHARE_ID);

    // Verify the encrypted key: unwrapping it with bob's private key must yield the new root
    // write key — confirmed by using it to unseal the new root's write-body.
    const wrappedBytes = Uint8Array.from(atob(encryptedWriteKey), (c) => c.charCodeAt(0));
    const unwrappedKey = await unwrapKey(wrappedBytes, bob.privateKey);
    expect(unwrappedKey).toBeInstanceOf(Uint8Array);
    expect(unwrappedKey.length).toBe(32);
    // Use the unwrapped key to open the new root's write-body; proves it is the actual
    // new root write key, not just any 32-byte value (WRITE-03 correctness gate).
    const survivorView = await unsealNode(newRootPub, rootReadKey, unwrappedKey);
    expect(survivorView.writeBody).toBeDefined();
    expect(survivorView.writeBody!.ipnsPrivateKey).toBeInstanceOf(Uint8Array);
    expect(survivorView.writeBody!.ipnsPrivateKey.length).toBe(32);
    unwrappedKey.fill(0); // zero after verification

    // Revoked recipient: deleteWriteGrantFn called; encryptedWriteKeyPersistFn NOT called for them.
    expect(deleteWriteGrantFn).toHaveBeenCalledWith(REVOKED_SHARE_ID);
    expect(encryptedWriteKeyPersistFn).not.toHaveBeenCalledWith(
      REVOKED_SHARE_ID,
      expect.anything()
    );

    // -----------------------------------------------------------------------
    // Read-plane invariance (D-06 / ADR 0001):
    // write-rotation must NOT bump generation or change readKey.
    // -----------------------------------------------------------------------

    // The old IPNS names still resolve (they are not tombstoned in IPNS — the TEE
    // simply stops re-publishing them; the data remains accessible until GC).
    const oldRootPub = await fetchPublishedEnvelope(oldRootIpnsName, aliceCtx);
    const oldChildPub = await fetchPublishedEnvelope(oldChildIpnsName, aliceCtx);
    expect(oldRootPub.generation).toBe(0); // unchanged
    expect(oldChildPub.generation).toBe(0); // unchanged

    // New nodes also carry the same generation (write-revoke is read-plane independent).
    expect(newRootPub.generation).toBe(0);
    expect(newChildPub.generation).toBe(0);

    // The new root still unseals under the original readKey (read plane unchanged).
    const newRootReadPlane = await unsealNode(newRootPub, rootReadKey);
    expect(newRootReadPlane.id).toBe(rootNodeId);
    expect(newRootReadPlane.generation).toBe(0);
  }, 120_000);
});
