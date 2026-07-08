/**
 * Rotation crash-safety suite (TEST-01 phase gate) — Phase 64, strengthened Phase 70.
 *
 * Four scenarios against the live local API stack:
 *   1. Happy-path: depth-2 tree (root → subfolder → file) rotates cleanly;
 *      multi-level D-02 re-seal proven by post-rotation read-chain navigation.
 *   2. Abort-and-resume: rotation crashes at the final persist callback (after
 *      all nodes commit and all D-09 batched re-publishes complete); a fresh
 *      resume job record converges without double-bumping any node (ROT-06/D-03);
 *      the pre-rotation grant is behind-retry after the root-step commit.
 *   3. Concurrent-add merge: a direct IPNS write to a parent between the root
 *      commit and the D-09 batched re-publish forces a CAS-409; the HIGH-4 merge
 *      (ROT-05) absorbs it and the concurrently-added child survives in the final
 *      parent state after the walk. Strengthened (Plan 70-08 / SC#1 / T-70-15):
 *      the test also NAVIGATES into the pre-existing rotated child (sub3IpnsName)
 *      and UNSEALS it with the new root key — proving local-wins (this phase's
 *      merge fix) keeps the existing rotated child's D-02 re-seal intact, where
 *      the old remote-wins merge would silently downgrade it to a stale seal that
 *      AEAD-fails on unseal. Also asserts the concurrent-write injection actually
 *      ran (fail-fast guard — a silently-skipped injection would make the test
 *      vacuously pass without exercising the CAS-409 merge path at all).
 *   4. Genuine fresh-record resume, mid-walk crash (Plan 70-08 / SC#3 / T-70-16):
 *      rotation crashes immediately after the root's OWN commit — earlier than
 *      scenario 2's final-persist crash — then resumes with a BRAND-NEW
 *      RotationJobRecord (empty completedNodeIds, no seeded state) and the
 *      CURRENT valid rootReadKey (captured via the crypto spy, standing in for a
 *      caller that legitimately still knows the current key — Open Question 1's
 *      narrowed scope). The root is a single file (no children) by deliberate
 *      design: any node WITH children whose own D-09 batched parent-republish has
 *      not yet fired leaves its SealedChildRef[...].readKeySealed entries wrapped
 *      under that node's PRE-rotation key, which cannot be re-derived from its
 *      POST-rotation "current" key — an unrecoverable AEAD-mismatch window
 *      documented in RESEARCH.md Pitfall 4 (no cryptographic recovery from the
 *      durable floor, which stores generation/sequence numbers only). A childless
 *      root sidesteps that window entirely while still proving the SC#3
 *      entry-gate's safe-double-rotation control flow end to end: the resume
 *      does NOT skip (fresh job, empty completedNodeIds) and re-rotates the root
 *      a SECOND time (generation 1 → 2), converging without seeding
 *      completedNodeIds or synthesizing a key — and the pre-rotation grant is cut
 *      (behind-retry) after the root step.
 *
 * Fault-injection note (D-03):
 *   The abort-and-resume crash (scenario 2) is injected via a test-only
 *   `persistCallback` that throws after the final (4th) call — i.e. after all 3
 *   nodes have committed and all D-09 parent re-publishes have completed. This is
 *   the only crash point at which the dirty-resume path (verifySubtreeClean) can
 *   reconstruct the frontier without needing the intermediate key material. The
 *   engine's resume path works correctly in this scenario: isDirty=false, no
 *   double-bump.
 *   The genuine fresh-record-resume crash (scenario 4) is injected via the SAME
 *   `persistCallback` mechanism, but throws on the FIRST call (right after the
 *   root's own commit) — see scenario 4's note above for why the root is
 *   deliberately childless.
 *
 * No production fault-injection code is added to any package under packages/.
 *
 * Prerequisites (live local stack):
 *   docker compose -f docker/docker-compose.yml up -d   (redis 6380, kubo, postgres)
 *   pnpm --filter @cipherbox/api dev                    (API on :3000)
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  addFilePointerToFolder,
  addToIpfs,
  createAndPublishIpnsRecord,
  createSubfolder,
  fetchFromIpfs,
  issueReadGrant,
  navigateReadChain,
  resolveIpnsRecord,
  rotateReadFromNode,
  type RotationJobRecord,
  type SdkContext,
  updateFolderMetadataAndPublish,
} from '@cipherbox/sdk-core';
import { sealNode, unsealChildReadKey, unsealNode } from '@cipherbox/core';
import type { Node, PublishedNode } from '@cipherbox/core';
import {
  deriveEd25519PublicKey,
  deriveIpnsName,
  generateEd25519Keypair,
  generateRandomBytes,
} from '@cipherbox/crypto';
import { type MultiAccountFixture, createMultiAccountFixture } from '../fixtures/multi-account';

// ---------------------------------------------------------------------------
// Shared fixture and spy
// ---------------------------------------------------------------------------

let fixture: MultiAccountFixture;

/**
 * 32-byte values captured from crypto.getRandomValues during rotation.
 *
 * rotateOne calls `crypto.getRandomValues(new Uint8Array(32))` to mint readKeyPrime.
 * mintFileKeyOnRotate calls `generateRandomBytes(32)` → same underlying call.
 *
 * Reset via clearCapturedReadKeys() immediately before each rotateReadFromNode
 * call so indices are stable: [0]=readKeyPrime_root, [1]=readKeyPrime_first-child, …
 */
const capturedReadKeys: Uint8Array[] = [];

/** Zero each captured key buffer before truncating the array. */
function clearCapturedReadKeys(): void {
  for (const key of capturedReadKeys) {
    key.fill(0);
  }
  capturedReadKeys.length = 0;
}

beforeAll(async () => {
  fixture = await createMultiAccountFixture(['alice', 'bob']);

  // Install spy ONCE for the whole suite. The original is called first so callers
  // receive real random bytes. We only intercept 32-byte calls (readKeyPrime/fileKeyPrime).
  const origGetRV = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
  vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (array: any) => {
      origGetRV(array as ArrayBufferView);
      if (array instanceof Uint8Array && array.length === 32) {
        capturedReadKeys.push(new Uint8Array(array));
      }
      return array;
    }
  );
});

afterAll(async () => {
  clearCapturedReadKeys();
  vi.restoreAllMocks();
  if (fixture) await fixture.cleanupAll();
});

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const PLACEHOLDER_CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';

/** Resolve IPNS and return the plaintext PublishedNode envelope (generation is AAD-plaintext). */
async function fetchPublishedEnvelope(ipnsName: string, ctx: SdkContext): Promise<PublishedNode> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) throw new Error(`fetchPublishedEnvelope: IPNS not found: ${ipnsName}`);
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}

/** Build a minimal file Node with placeholder content. */
function makeFileNode(): { node: Node; readKey: Uint8Array } {
  const readKey = generateRandomBytes(32);
  const node: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: crypto.randomUUID(),
    generation: 0,
    createdAt: Date.now(),
    modifiedAt: Date.now(),
    content: {
      cid: PLACEHOLDER_CID,
      fileIv: Array.from(generateRandomBytes(12))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(''),
      size: 42,
      mimeType: 'text/plain',
      encryptionMode: 'GCM',
      fileKey: generateRandomBytes(32),
      versions: [],
    },
  };
  return { node, readKey };
}

/** Seal a file node, upload to IPFS, publish to a fresh IPNS keypair (seq 1n). */
async function publishFileNode(
  node: Node,
  readKey: Uint8Array,
  ctx: SdkContext
): Promise<{ ipnsName: string; keypair: { privateKey: Uint8Array; publicKey: Uint8Array } }> {
  const keypair = generateEd25519Keypair(); // synchronous
  const ipnsName = await deriveIpnsName(keypair.publicKey);
  const dummyWriteKey = new Uint8Array(32);
  const pub = await sealNode(node, readKey, dummyWriteKey);
  const { cid } = await addToIpfs(ctx, new TextEncoder().encode(JSON.stringify(pub)));
  await createAndPublishIpnsRecord({
    ipnsPrivateKey: keypair.privateKey,
    ipnsPublicKey: keypair.publicKey,
    ipnsName,
    metadataCid: cid,
    sequenceNumber: 1n, // MUST be 1n for first publish (Phase-60 strict gate)
    ctx,
  });
  return { ipnsName, keypair };
}

// ---------------------------------------------------------------------------
// Test 1: Happy-path — depth-2 rotation + read-chain navigation
// ---------------------------------------------------------------------------

describe('Rotation crash-safety suite (TEST-01 phase gate)', () => {
  it('happy-path: depth-2 tree rotates cleanly and read-chain navigates under new keys (D-02)', async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;
    const aliceCtx = alice.client.getContext();
    const bobCtx = bob.client.getContext();

    // --- Build tree: root → subfolder → file ---

    const rootResult = await createSubfolder({ name: 'hp-root', ctx: aliceCtx });
    const rootIpnsPublicKey = deriveEd25519PublicKey(rootResult.ipnsPrivateKey);
    const rootIpnsName = await deriveIpnsName(rootIpnsPublicKey);

    const subResult = await createSubfolder({ name: 'hp-sub', ctx: aliceCtx });
    const subIpnsPublicKey = deriveEd25519PublicKey(subResult.ipnsPrivateKey);
    const subIpnsName = await deriveIpnsName(subIpnsPublicKey);

    const { node: fileNode, readKey: fileReadKey } = makeFileNode();
    const { ipnsName: fileIpnsName, keypair: fileKeypair } = await publishFileNode(
      fileNode,
      fileReadKey,
      aliceCtx
    );

    // Link file → subfolder (subfolder seals fileReadKey under subfolderReadKey)
    const { updatedChildren: subChildren } = await addFilePointerToFolder({
      children: [],
      childReadKey: fileReadKey,
      parentReadKey: subResult.rootReadKey,
      childId: fileNode.id,
      childKind: 'file',
      childGeneration: 0,
      name: 'file.txt',
      ipnsName: fileIpnsName,
      versionFloor: 0n,
    });
    await updateFolderMetadataAndPublish({
      children: subChildren,
      readKey: subResult.rootReadKey,
      ipnsPrivateKey: subResult.ipnsPrivateKey,
      ipnsPublicKey: subIpnsPublicKey,
      ipnsName: subIpnsName,
      sequenceNumber: 1n,
      nodeId: subResult.node.id,
      nodeGeneration: subResult.node.generation,
      ctx: aliceCtx,
    });

    // Link subfolder → root (root seals subReadKey under rootReadKey)
    const { updatedChildren: rootChildren } = await addFilePointerToFolder({
      children: [],
      childReadKey: subResult.rootReadKey,
      parentReadKey: rootResult.rootReadKey,
      childId: subResult.node.id,
      childKind: 'folder',
      childGeneration: 0,
      name: 'subfolder',
      ipnsName: subIpnsName,
      versionFloor: 0n,
    });
    await updateFolderMetadataAndPublish({
      children: rootChildren,
      readKey: rootResult.rootReadKey,
      ipnsPrivateKey: rootResult.ipnsPrivateKey,
      ipnsPublicKey: rootIpnsPublicKey,
      ipnsName: rootIpnsName,
      sequenceNumber: 1n,
      nodeId: rootResult.node.id,
      nodeGeneration: rootResult.node.generation,
      ctx: aliceCtx,
    });

    // Key map for nodeKeySource (D-01 fail-closed: every frontier node needs its IPNS key)
    const keyMap = new Map([
      [rootIpnsName, { privateKey: rootResult.ipnsPrivateKey, publicKey: rootIpnsPublicKey }],
      [subIpnsName, { privateKey: subResult.ipnsPrivateKey, publicKey: subIpnsPublicKey }],
      [fileIpnsName, { privateKey: fileKeypair.privateKey, publicKey: fileKeypair.publicKey }],
    ]);
    const nodeKeySource = (name: string) => keyMap.get(name);

    // Issue pre-rotation grant to Bob
    const { readDescriptorRef: preGrant } = await issueReadGrant({
      shareRootReadKey: rootResult.rootReadKey,
      recipientPublicKey: bob.publicKey,
      rootNodeId: rootResult.node.id,
      rootIpnsName: rootIpnsName,
      rootGeneration: 0,
      insertShareFn: async (_p) => ({ shareId: crypto.randomUUID() }),
    });

    // --- Rotate the full tree ---
    clearCapturedReadKeys();
    const jobRecord: RotationJobRecord = {
      rootNodeId: rootResult.node.id,
      status: 'pending',
      completedNodeIds: new Set(),
      frontier: [],
    };
    await rotateReadFromNode({
      rootNodeId: rootResult.node.id,
      rootNodeIpnsName: rootIpnsName,
      rootReadKey: rootResult.rootReadKey,
      rootIpnsPrivateKey: rootResult.ipnsPrivateKey,
      rootIpnsPublicKey: rootIpnsPublicKey,
      jobRecord,
      ctx: aliceCtx,
      nodeKeySource,
    });

    // capturedReadKeys[0] = readKeyPrime for root (first 32-byte call inside rotateOne)
    const readKeyPrimeRoot = capturedReadKeys[0];
    expect(readKeyPrimeRoot).toBeInstanceOf(Uint8Array);
    expect(readKeyPrimeRoot.length).toBe(32);
    expect(jobRecord.status).toBe('complete');

    // All nodes advance generation by 1
    const rootPub = await fetchPublishedEnvelope(rootIpnsName, aliceCtx);
    const subPub = await fetchPublishedEnvelope(subIpnsName, aliceCtx);
    const filePub = await fetchPublishedEnvelope(fileIpnsName, aliceCtx);
    expect(rootPub.generation).toBe(1);
    expect(subPub.generation).toBe(1);
    expect(filePub.generation).toBe(1);

    // Pre-rotation grant is now revoked (behind-retry)
    const revokedResult = await navigateReadChain({
      readDescriptorRef: preGrant,
      recipientPrivKey: bob.privateKey,
      rootIpnsName: rootIpnsName,
      rootExpectedGeneration: 0,
      path: [subIpnsName, fileIpnsName],
      ctx: bobCtx,
    });
    expect(revokedResult.status).toBe('behind-retry');

    // Post-rotation grant navigates root → subfolder → file (D-02: multi-level re-seal proven)
    const { readDescriptorRef: freshGrant } = await issueReadGrant({
      shareRootReadKey: readKeyPrimeRoot,
      recipientPublicKey: bob.publicKey,
      rootNodeId: rootResult.node.id,
      rootIpnsName: rootIpnsName,
      rootGeneration: 1,
      insertShareFn: async (_p) => ({ shareId: crypto.randomUUID() }),
    });
    const navResult = await navigateReadChain({
      readDescriptorRef: freshGrant,
      recipientPrivKey: bob.privateKey,
      rootIpnsName: rootIpnsName,
      rootExpectedGeneration: 1,
      path: [subIpnsName, fileIpnsName],
      ctx: bobCtx,
    });
    expect(navResult.status).toBe('ok');
    if (navResult.status === 'ok') {
      expect(navResult.content?.cid).toBeTruthy();
      expect(navResult.content?.fileKey).toBeInstanceOf(Uint8Array);
    }
  }, 120_000);

  // ---------------------------------------------------------------------------
  // Test 2: Abort-and-resume (crash at final persist → no double-bump)
  // ---------------------------------------------------------------------------

  it('abort-and-resume: crash at final persist → fresh resume → no double-bump → revocation cut', async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;
    const aliceCtx = alice.client.getContext();
    const bobCtx = bob.client.getContext();

    // --- Build tree: root2 → subfolder2 → file2 ---

    const root2Result = await createSubfolder({ name: 'ar-root', ctx: aliceCtx });
    const root2IpnsPublicKey = deriveEd25519PublicKey(root2Result.ipnsPrivateKey);
    const root2IpnsName = await deriveIpnsName(root2IpnsPublicKey);

    const sub2Result = await createSubfolder({ name: 'ar-sub', ctx: aliceCtx });
    const sub2IpnsPublicKey = deriveEd25519PublicKey(sub2Result.ipnsPrivateKey);
    const sub2IpnsName = await deriveIpnsName(sub2IpnsPublicKey);

    const { node: file2Node, readKey: file2ReadKey } = makeFileNode();
    const { ipnsName: file2IpnsName, keypair: file2Keypair } = await publishFileNode(
      file2Node,
      file2ReadKey,
      aliceCtx
    );

    // Link file2 → subfolder2
    const { updatedChildren: sub2Children } = await addFilePointerToFolder({
      children: [],
      childReadKey: file2ReadKey,
      parentReadKey: sub2Result.rootReadKey,
      childId: file2Node.id,
      childKind: 'file',
      childGeneration: 0,
      name: 'file2.txt',
      ipnsName: file2IpnsName,
      versionFloor: 0n,
    });
    await updateFolderMetadataAndPublish({
      children: sub2Children,
      readKey: sub2Result.rootReadKey,
      ipnsPrivateKey: sub2Result.ipnsPrivateKey,
      ipnsPublicKey: sub2IpnsPublicKey,
      ipnsName: sub2IpnsName,
      sequenceNumber: 1n,
      nodeId: sub2Result.node.id,
      nodeGeneration: sub2Result.node.generation,
      ctx: aliceCtx,
    });

    // Link subfolder2 → root2
    const { updatedChildren: root2Children } = await addFilePointerToFolder({
      children: [],
      childReadKey: sub2Result.rootReadKey,
      parentReadKey: root2Result.rootReadKey,
      childId: sub2Result.node.id,
      childKind: 'folder',
      childGeneration: 0,
      name: 'subfolder2',
      ipnsName: sub2IpnsName,
      versionFloor: 0n,
    });
    await updateFolderMetadataAndPublish({
      children: root2Children,
      readKey: root2Result.rootReadKey,
      ipnsPrivateKey: root2Result.ipnsPrivateKey,
      ipnsPublicKey: root2IpnsPublicKey,
      ipnsName: root2IpnsName,
      sequenceNumber: 1n,
      nodeId: root2Result.node.id,
      nodeGeneration: root2Result.node.generation,
      ctx: aliceCtx,
    });

    // Pre-rotation grant to Bob (will become stale after rotation)
    const { readDescriptorRef: preGrant2 } = await issueReadGrant({
      shareRootReadKey: root2Result.rootReadKey,
      recipientPublicKey: bob.publicKey,
      rootNodeId: root2Result.node.id,
      rootIpnsName: root2IpnsName,
      rootGeneration: 0,
      insertShareFn: async (_p) => ({ shareId: crypto.randomUUID() }),
    });

    const keyMap2 = new Map([
      [root2IpnsName, { privateKey: root2Result.ipnsPrivateKey, publicKey: root2IpnsPublicKey }],
      [sub2IpnsName, { privateKey: sub2Result.ipnsPrivateKey, publicKey: sub2IpnsPublicKey }],
      [file2IpnsName, { privateKey: file2Keypair.privateKey, publicKey: file2Keypair.publicKey }],
    ]);
    const nodeKeySource2 = (name: string) => keyMap2.get(name);

    // --- Crash run: throw at the 4th persistCallback call (final status='complete').
    //
    // For a 3-node tree (root, subfolder, file), the engine calls persistCallback 4×:
    //   call 1: after root commits
    //   call 2: after subfolder commits  (D-09 for root fires AFTER this call)
    //   call 3: after file commits       (D-09 for subfolder fires AFTER this call)
    //   call 4: final — status='complete' (all D-09 parent republishes already done)
    //
    // Throwing at call 4 means all nodes ARE committed (gen=1) and all D-09 parent
    // republishes ARE complete, but the host's persistence of 'complete' status fails.
    // verifySubtreeClean on resume: isDirty=false → job marks complete, no re-rotation.
    let persistCallCount = 0;
    const crashingPersist = (_job: RotationJobRecord): void => {
      persistCallCount++;
      if (persistCallCount >= 4) {
        throw new Error('simulated-crash-at-final-persist');
      }
    };

    clearCapturedReadKeys();
    const jobRecord2: RotationJobRecord = {
      rootNodeId: root2Result.node.id,
      status: 'pending',
      completedNodeIds: new Set(),
      frontier: [],
      persistCallback: crashingPersist,
    };

    let crashed = false;
    try {
      await rotateReadFromNode({
        rootNodeId: root2Result.node.id,
        rootNodeIpnsName: root2IpnsName,
        rootReadKey: root2Result.rootReadKey,
        rootIpnsPrivateKey: root2Result.ipnsPrivateKey,
        rootIpnsPublicKey: root2IpnsPublicKey,
        jobRecord: jobRecord2,
        ctx: aliceCtx,
        nodeKeySource: nodeKeySource2,
      });
    } catch (err) {
      crashed = true;
      expect((err as Error).message).toContain('simulated-crash-at-final-persist');
    }
    expect(crashed).toBe(true);
    expect(persistCallCount).toBe(4); // 3 nodes + final status

    // readKeyPrime_root2 captured before the persistCallback (spy fires inside rotateOne).
    // Use .slice() to make an independent copy: clearCapturedReadKeys() below zeros
    // capturedReadKeys[0] in place; without a copy, readKeyPrimeRoot2 would become
    // all-zeros before being passed to rotateReadFromNode.
    const readKeyPrimeRoot2 = capturedReadKeys[0].slice();
    expect(readKeyPrimeRoot2).toBeInstanceOf(Uint8Array);

    // All 3 nodes committed before crash
    expect(
      await (async () => (await fetchPublishedEnvelope(root2IpnsName, aliceCtx)).generation)()
    ).toBe(1);
    expect(
      await (async () => (await fetchPublishedEnvelope(sub2IpnsName, aliceCtx)).generation)()
    ).toBe(1);
    expect(
      await (async () => (await fetchPublishedEnvelope(file2IpnsName, aliceCtx)).generation)()
    ).toBe(1);

    // Pre-rotation grant is revoked (root committed → published gen=1 > expected gen=0)
    const revokedNav = await navigateReadChain({
      readDescriptorRef: preGrant2,
      recipientPrivKey: bob.privateKey,
      rootIpnsName: root2IpnsName,
      rootExpectedGeneration: 0,
      path: [sub2IpnsName, file2IpnsName],
      ctx: bobCtx,
    });
    expect(revokedNav.status).toBe('behind-retry');

    // --- Fresh resume: seeded with crash-time completedNodeIds, new rootReadKey.
    //
    // "Fresh" = a new RotationJobRecord object. completedNodeIds seeded from
    // the crash-time advisory state (jobRecord2.completedNodeIds) because a real
    // host's persistCallback would have checkpointed these IDs at calls 1-3.
    // rootReadKey = readKeyPrimeRoot2 (the post-rotation key root2 is sealed under).
    // verifySubtreeClean → isDirty=false → marks job complete without re-rotating.
    const freshJob: RotationJobRecord = {
      rootNodeId: root2Result.node.id,
      status: 'pending',
      completedNodeIds: new Set(jobRecord2.completedNodeIds),
      frontier: [],
    };

    clearCapturedReadKeys(); // should stay empty — no rotation on resume
    let resumeError: unknown;
    try {
      await rotateReadFromNode({
        rootNodeId: root2Result.node.id,
        rootNodeIpnsName: root2IpnsName,
        rootReadKey: readKeyPrimeRoot2, // NEW sealed key
        rootIpnsPrivateKey: root2Result.ipnsPrivateKey,
        rootIpnsPublicKey: root2IpnsPublicKey,
        jobRecord: freshJob,
        ctx: aliceCtx,
        nodeKeySource: nodeKeySource2,
      });
    } catch (err) {
      resumeError = err;
    }
    expect(resumeError).toBeUndefined(); // must converge without throwing
    expect(freshJob.status).toBe('complete');

    // No double-bump: all nodes remain at generation 1 (not 2)
    expect(
      await (async () => (await fetchPublishedEnvelope(root2IpnsName, aliceCtx)).generation)()
    ).toBe(1);
    expect(
      await (async () => (await fetchPublishedEnvelope(sub2IpnsName, aliceCtx)).generation)()
    ).toBe(1);
    expect(
      await (async () => (await fetchPublishedEnvelope(file2IpnsName, aliceCtx)).generation)()
    ).toBe(1);

    // No getRandomValues calls during resume (verifySubtreeClean = read-only)
    expect(capturedReadKeys.length).toBe(0);

    // Post-resume navigation works with the new root readKey
    const { readDescriptorRef: freshGrant2 } = await issueReadGrant({
      shareRootReadKey: readKeyPrimeRoot2,
      recipientPublicKey: bob.publicKey,
      rootNodeId: root2Result.node.id,
      rootIpnsName: root2IpnsName,
      rootGeneration: 1,
      insertShareFn: async (_p) => ({ shareId: crypto.randomUUID() }),
    });
    const postResumeNav = await navigateReadChain({
      readDescriptorRef: freshGrant2,
      recipientPrivKey: bob.privateKey,
      rootIpnsName: root2IpnsName,
      rootExpectedGeneration: 1,
      path: [sub2IpnsName, file2IpnsName],
      ctx: bobCtx,
    });
    expect(postResumeNav.status).toBe('ok');
  }, 120_000);

  // ---------------------------------------------------------------------------
  // Test 3: Concurrent-add-during-rotation merge (HIGH-4 §7.3 test 4)
  // ---------------------------------------------------------------------------

  it('concurrent-add: child added mid-rotation survives in merged parent (HIGH-4/ROT-05)', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    // --- Build tree: root3 → subfolder3 (single child) ---

    const root3Result = await createSubfolder({ name: 'ca-root', ctx: aliceCtx });
    const root3IpnsPublicKey = deriveEd25519PublicKey(root3Result.ipnsPrivateKey);
    const root3IpnsName = await deriveIpnsName(root3IpnsPublicKey);

    const sub3Result = await createSubfolder({ name: 'ca-sub', ctx: aliceCtx });
    const sub3IpnsPublicKey = deriveEd25519PublicKey(sub3Result.ipnsPrivateKey);
    const sub3IpnsName = await deriveIpnsName(sub3IpnsPublicKey);

    // Link subfolder3 → root3
    const { updatedChildren: root3Children } = await addFilePointerToFolder({
      children: [],
      childReadKey: sub3Result.rootReadKey,
      parentReadKey: root3Result.rootReadKey,
      childId: sub3Result.node.id,
      childKind: 'folder',
      childGeneration: 0,
      name: 'subfolder3',
      ipnsName: sub3IpnsName,
      versionFloor: 0n,
    });
    await updateFolderMetadataAndPublish({
      children: root3Children,
      readKey: root3Result.rootReadKey,
      ipnsPrivateKey: root3Result.ipnsPrivateKey,
      ipnsPublicKey: root3IpnsPublicKey,
      ipnsName: root3IpnsName,
      sequenceNumber: 1n,
      nodeId: root3Result.node.id,
      nodeGeneration: root3Result.node.generation,
      ctx: aliceCtx,
    });

    // Create the concurrent child BEFORE the rotation starts (avoids spy capture noise)
    const concurrentResult = await createSubfolder({ name: 'ca-concurrent', ctx: aliceCtx });
    const concurrentIpnsPublicKey = deriveEd25519PublicKey(concurrentResult.ipnsPrivateKey);
    const concurrentIpnsName = await deriveIpnsName(concurrentIpnsPublicKey);
    const concurrentReadKey = concurrentResult.rootReadKey;
    const concurrentNodeId = concurrentResult.node.id;

    const keyMap3 = new Map([
      [root3IpnsName, { privateKey: root3Result.ipnsPrivateKey, publicKey: root3IpnsPublicKey }],
      [sub3IpnsName, { privateKey: sub3Result.ipnsPrivateKey, publicKey: sub3IpnsPublicKey }],
    ]);
    const nodeKeySource3 = (name: string) => keyMap3.get(name);

    // --- Inject concurrent add via persistCallback.
    //
    // Timing (2-node tree: root3, subfolder3):
    //   call 1: after root3 commits → concurrent add fires HERE
    //   call 2: after subfolder3 commits
    //           → D-09 for root3 fires AFTER this call
    //           → CAS-409 because concurrent add already advanced root3's seq
    //           → publishWithCas merges: concurrentChild survives
    //   call 3: final status='complete'
    let persistCall3Count = 0;
    // T-70-15: fail-fast guard — if the injection body never actually runs
    // (e.g. a refactor changes the persistCallback call count/ordering), this
    // test must FAIL rather than silently passing without ever exercising the
    // CAS-409 merge path it claims to prove.
    let concurrentInjectionRan = false;
    const concurrentAddPersist = async (_job: RotationJobRecord): Promise<void> => {
      persistCall3Count++;
      if (persistCall3Count !== 1) return; // only inject on first call (after root3 commits)

      // capturedReadKeys[0] = readKeyPrime_root3 (captured inside rotateOne for root3,
      // which fires BEFORE the persistCallback is called)
      const rootReadKeyPrime = capturedReadKeys[0];
      if (!rootReadKeyPrime) return; // safety: should always be set at this point

      // Resolve root3's current IPNS state (gen=1, sealed under rootReadKeyPrime)
      const resolved = await resolveIpnsRecord(root3IpnsName, aliceCtx);
      if (!resolved) return;
      const raw = await fetchFromIpfs(aliceCtx, resolved.cid);
      const pub = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;

      // Unseal root3 to get its current children (subfolder3 with original readKeySealed)
      const root3NodeCurrent = await unsealNode(pub, rootReadKeyPrime);
      const currentChildren = root3NodeCurrent.children ?? [];

      // Add the concurrent child to root3 (sealed under rootReadKeyPrime)
      const { updatedChildren: withConcurrent } = await addFilePointerToFolder({
        children: currentChildren,
        childReadKey: concurrentReadKey,
        parentReadKey: rootReadKeyPrime,
        childId: concurrentNodeId,
        childKind: 'folder',
        childGeneration: 0,
        name: 'concurrent-folder',
        ipnsName: concurrentIpnsName,
        versionFloor: 0n,
      });

      // Publish to root3's IPNS (advances seq by 1 beyond the rotation engine's record).
      // When D-09 fires for root3 after subfolder3 commits, publishWithCas sees a seq
      // conflict and calls mergeChildren → concurrentChild survives in the merged result.
      await updateFolderMetadataAndPublish({
        children: withConcurrent,
        readKey: rootReadKeyPrime,
        ipnsPrivateKey: root3Result.ipnsPrivateKey,
        ipnsPublicKey: root3IpnsPublicKey,
        ipnsName: root3IpnsName,
        sequenceNumber: resolved.sequenceNumber, // publishWithCas will publish at +1
        nodeId: root3Result.node.id,
        nodeGeneration: pub.generation, // 1 (post-rotation)
        ctx: aliceCtx,
      });
      concurrentInjectionRan = true;
    };

    clearCapturedReadKeys();
    const jobRecord3: RotationJobRecord = {
      rootNodeId: root3Result.node.id,
      status: 'pending',
      completedNodeIds: new Set(),
      frontier: [],
      persistCallback: concurrentAddPersist,
    };

    // Rotation must complete without throwing — CAS-409 is merged internally by publishWithCas
    await rotateReadFromNode({
      rootNodeId: root3Result.node.id,
      rootNodeIpnsName: root3IpnsName,
      rootReadKey: root3Result.rootReadKey,
      rootIpnsPrivateKey: root3Result.ipnsPrivateKey,
      rootIpnsPublicKey: root3IpnsPublicKey,
      jobRecord: jobRecord3,
      ctx: aliceCtx,
      nodeKeySource: nodeKeySource3,
    });
    expect(jobRecord3.status).toBe('complete');
    // 2-node tree (root3, subfolder3): 3 persistCallback checkpoints —
    // root3 commit, subfolder3 commit, final status='complete'.
    expect(persistCall3Count).toBe(3);
    // T-70-15: fail fast if the concurrent-write injection never actually ran —
    // see the guard declaration above for why this must be asserted explicitly.
    expect(concurrentInjectionRan).toBe(true);

    // --- Assert: concurrent child survives in the final merged root3 ---
    const readKeyPrimeRoot3 = capturedReadKeys[0];
    expect(readKeyPrimeRoot3).toBeInstanceOf(Uint8Array);

    const root3FinalPub = await fetchPublishedEnvelope(root3IpnsName, aliceCtx);
    expect(root3FinalPub.generation).toBe(1); // root3 rotated

    // Unseal root3 with readKeyPrime_root3 and inspect the merged children
    const root3Resolved = await resolveIpnsRecord(root3IpnsName, aliceCtx);
    const root3Raw = await fetchFromIpfs(aliceCtx, root3Resolved!.cid);
    const root3FinalNode = await unsealNode(
      JSON.parse(new TextDecoder().decode(root3Raw)) as PublishedNode,
      readKeyPrimeRoot3
    );
    const childIpnsNames = (root3FinalNode.children ?? []).map((c) => c.ipnsName);

    // ROT-05/HIGH-4: concurrently-added child must survive the CAS-409 merge
    expect(childIpnsNames).toContain(concurrentIpnsName);
    // subfolder3 must also still be present (not dropped by the merge)
    expect(childIpnsNames).toContain(sub3IpnsName);

    // --- T-70-15 (Plan 70-08 / SC#1): navigate into subfolder3 and UNSEAL it
    // with the NEW root key — proving local-wins kept the pre-existing rotated
    // child's D-02 re-seal intact.
    //
    // Under the OLD remote-wins merge, the `remote` view (the concurrent
    // write's snapshot, captured BEFORE subfolder3 itself finished rotating)
    // still pointed subfolder3's SealedChildRef.readKeySealed at subfolder3's
    // PRE-rotation key. A name-only assertion (childIpnsNames.toContain above)
    // cannot detect this — the entry survives under either policy, only its
    // WRAPPED KEY differs. Deriving and unsealing subfolder3's ACTUAL published
    // (post-rotation) body with that stale pointer AEAD-fails; local-wins (this
    // phase's fix) keeps rotation's own D-09 view, which points at subfolder3's
    // POST-rotation key, so the unseal below must succeed.
    const sub3ChildRef = (root3FinalNode.children ?? []).find((c) => c.ipnsName === sub3IpnsName);
    expect(sub3ChildRef).toBeDefined();
    const sub3Pub = await fetchPublishedEnvelope(sub3IpnsName, aliceCtx);
    expect(sub3Pub.generation).toBe(1); // subfolder3 itself was rotated by the walk
    const sub3ReadKey = await unsealChildReadKey(
      sub3ChildRef!.readKeySealed,
      readKeyPrimeRoot3,
      sub3Pub.id,
      sub3Pub.kind,
      sub3ChildRef!.generation
    );
    // try/finally so this owned key buffer is still zeroed if the assertion
    // below throws (T9) — a bare trailing `.fill(0)` after the assertion is
    // skipped entirely on failure, leaking the key material.
    try {
      // The actual unseal — this is what AEAD-fails under the old remote-wins bug.
      const sub3Node = await unsealNode(sub3Pub, sub3ReadKey);
      expect(sub3Node.id).toBe(sub3Result.node.id);
    } finally {
      sub3ReadKey.fill(0);
    }
  }, 120_000);

  // ---------------------------------------------------------------------------
  // Test 4: Genuine fresh-record resume — mid-walk crash (Plan 70-08 / SC#3)
  // ---------------------------------------------------------------------------

  it('fresh-record resume: mid-walk crash → resume with EMPTY completedNodeIds + current key → safe double-rotation → revocation cut', async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;
    const aliceCtx = alice.client.getContext();
    const bobCtx = bob.client.getContext();

    // --- Build a single-node "tree": root4 is a FILE, no children.
    //
    // Deliberate scope (see the file-header comment for scenario 4, and
    // RESEARCH.md Pitfall 4): a childless root is the only crash point in this
    // suite's persistCallback-only fault-injection model for which a fresh
    // (empty completedNodeIds) resume with the CURRENT valid rootReadKey is
    // cryptographically guaranteed to converge. Any node with children whose
    // own D-09 batched parent-republish has not yet fired leaves its
    // SealedChildRef[...].readKeySealed entries wrapped under that node's
    // PRE-rotation key — unrecoverable from the node's POST-rotation "current"
    // key with no cryptographic recovery path (Pitfall 4). This still proves
    // the SC#3 entry-gate's actual target: a fresh job record with empty
    // completedNodeIds must NOT get stuck (skip-gated) and must converge via
    // safe double-rotation using whatever key is genuinely current.
    const { node: root4Node, readKey: root4ReadKey } = makeFileNode();
    const { ipnsName: root4IpnsName, keypair: root4Keypair } = await publishFileNode(
      root4Node,
      root4ReadKey,
      aliceCtx
    );

    // Pre-rotation grant to Bob (will become stale after the crash-run's root commit).
    const { readDescriptorRef: preGrant4 } = await issueReadGrant({
      shareRootReadKey: root4ReadKey,
      recipientPublicKey: bob.publicKey,
      rootNodeId: root4Node.id,
      rootIpnsName: root4IpnsName,
      rootGeneration: 0,
      insertShareFn: async (_p) => ({ shareId: crypto.randomUUID() }),
    });

    // --- Crash run: throw on the FIRST persistCallback call — i.e. immediately
    // after root4's own commit. For a single-node tree this is the ONLY
    // checkpoint before the final status='complete' persist, so this is
    // strictly earlier than scenario 2's 4th/final-call crash.
    let persistCall4Count = 0;
    const crashingPersistMidWalk = (_job: RotationJobRecord): void => {
      persistCall4Count++;
      if (persistCall4Count >= 1) {
        throw new Error('simulated-crash-mid-walk-after-root-commit');
      }
    };

    clearCapturedReadKeys();
    const jobRecord4: RotationJobRecord = {
      rootNodeId: root4Node.id,
      status: 'pending',
      completedNodeIds: new Set(),
      frontier: [],
      persistCallback: crashingPersistMidWalk,
    };

    let crashed4 = false;
    try {
      await rotateReadFromNode({
        rootNodeId: root4Node.id,
        rootNodeIpnsName: root4IpnsName,
        rootReadKey: root4ReadKey,
        rootIpnsPrivateKey: root4Keypair.privateKey,
        rootIpnsPublicKey: root4Keypair.publicKey,
        jobRecord: jobRecord4,
        ctx: aliceCtx,
      });
    } catch (err) {
      crashed4 = true;
      expect((err as Error).message).toContain('simulated-crash-mid-walk-after-root-commit');
    }
    expect(crashed4).toBe(true);
    expect(persistCall4Count).toBe(1); // root4's commit checkpoint, nothing further

    // root4's own rotateOne CAS-publish committed BEFORE persistCallback threw
    // (checkpoint fires after the commit, per the walk's own ordering) — the
    // root cut already happened, this crash only interrupted the job's own
    // bookkeeping.
    const rootPub4AfterCrash = await fetchPublishedEnvelope(root4IpnsName, aliceCtx);
    expect(rootPub4AfterCrash.generation).toBe(1);

    // readKeyPrime_root4 captured before the persistCallback (spy fires inside
    // rotateOne, BEFORE mintFileKeyOnRotate's own 32-byte content-key mint —
    // capturedReadKeys[0] is always the node's own readKeyPrime, per the spy's
    // module docstring). .slice() makes an independent copy since
    // clearCapturedReadKeys() below zeros the array's buffers in place.
    const readKeyPrimeRoot4 = capturedReadKeys[0].slice();
    expect(readKeyPrimeRoot4).toBeInstanceOf(Uint8Array);
    expect(readKeyPrimeRoot4.length).toBe(32);

    // Pre-rotation grant is already cut (root committed → published gen=1 > expected gen=0).
    const revokedNav4 = await navigateReadChain({
      readDescriptorRef: preGrant4,
      recipientPrivKey: bob.privateKey,
      rootIpnsName: root4IpnsName,
      rootExpectedGeneration: 0,
      path: [],
      ctx: bobCtx,
    });
    expect(revokedNav4.status).toBe('behind-retry');

    // --- Genuine fresh-record resume: BRAND-NEW job record (empty
    // completedNodeIds — NOT seeded from jobRecord4's crash-time state) + the
    // CURRENT valid rootReadKey (readKeyPrimeRoot4 — root4's ACTUAL published
    // key right now; NOT the original pre-crash-run key, which would fail the
    // entry gate's stale-key probe since root4 already rotated once).
    //
    // Since completedNodeIds is empty, root4's own idempotency check
    // (rotateOne) does NOT skip it — root4 is rotated AGAIN (SAFE
    // DOUBLE-ROTATION, design §4.5 / Plan 70-06): generation 1 → 2. This is the
    // opposite of scenario 2's "no double-bump" assertion, by design — scenario
    // 2 seeds completedNodeIds (root already marked done, skipped); this
    // scenario deliberately does NOT, to prove the fresh-record path converges
    // on its own instead of getting stuck behind an empty-completedNodeIds gate.
    const freshJob4: RotationJobRecord = {
      rootNodeId: root4Node.id,
      status: 'pending',
      completedNodeIds: new Set(), // EMPTY — genuinely fresh, not seeded
      frontier: [],
    };

    clearCapturedReadKeys();
    let resumeError4: unknown;
    let resumeResult4: Awaited<ReturnType<typeof rotateReadFromNode>> = undefined;
    // try/finally so every owned key buffer from this fresh-resume path
    // (readKeyPrimeRoot4, resumeResult4.readKey, and any buffers captured
    // into `capturedReadKeys` during the resume's own rotation) is zeroed
    // even if an assertion below throws (T9) — a bare trailing `.fill(0)`
    // after the assertions is skipped entirely on failure, leaking the key
    // material for the rest of the suite run.
    try {
      try {
        resumeResult4 = await rotateReadFromNode({
          rootNodeId: root4Node.id,
          rootNodeIpnsName: root4IpnsName,
          rootReadKey: readKeyPrimeRoot4, // CURRENT valid key, not the original
          rootIpnsPrivateKey: root4Keypair.privateKey,
          rootIpnsPublicKey: root4Keypair.publicKey,
          jobRecord: freshJob4,
          ctx: aliceCtx,
        });
      } catch (err) {
        resumeError4 = err;
      }
      expect(resumeError4).toBeUndefined(); // must converge without throwing
      expect(freshJob4.status).toBe('complete');

      // Safe double-rotation: root4 is now at generation 2 (double-rotated), not
      // stuck at 1 — the opposite of scenario 2's no-double-bump assertion.
      const rootPub4AfterResume = await fetchPublishedEnvelope(root4IpnsName, aliceCtx);
      expect(rootPub4AfterResume.generation).toBe(2);

      // rotateReadFromNode returns the root's freshly minted key (root was NOT
      // skipped this run — a genuinely new rotation, not a dirty-resume republish).
      expect(resumeResult4).toBeDefined();
      expect(resumeResult4!.generation).toBe(2);
      expect(resumeResult4!.readKey).toBeInstanceOf(Uint8Array);
      // A genuinely NEW key was minted — not the same buffer/value as the
      // crash-run's key (proves an actual second rotation occurred, not a no-op).
      expect(resumeResult4!.readKey).not.toEqual(readKeyPrimeRoot4);

      // Pre-rotation grant remains cut after the resume's root step.
      const revokedNavAfterResume = await navigateReadChain({
        readDescriptorRef: preGrant4,
        recipientPrivKey: bob.privateKey,
        rootIpnsName: root4IpnsName,
        rootExpectedGeneration: 0,
        path: [],
        ctx: bobCtx,
      });
      expect(revokedNavAfterResume.status).toBe('behind-retry');

      // A freshly issued grant using the resume's new key navigates successfully.
      const { readDescriptorRef: freshGrant4 } = await issueReadGrant({
        shareRootReadKey: resumeResult4!.readKey,
        recipientPublicKey: bob.publicKey,
        rootNodeId: root4Node.id,
        rootIpnsName: root4IpnsName,
        rootGeneration: 2,
        insertShareFn: async (_p) => ({ shareId: crypto.randomUUID() }),
      });
      const postResumeNav4 = await navigateReadChain({
        readDescriptorRef: freshGrant4,
        recipientPrivKey: bob.privateKey,
        rootIpnsName: root4IpnsName,
        rootExpectedGeneration: 2,
        path: [],
        ctx: bobCtx,
      });
      expect(postResumeNav4.status).toBe('ok');
      if (postResumeNav4.status === 'ok') {
        expect(postResumeNav4.content?.cid).toBeTruthy();
      }
    } finally {
      readKeyPrimeRoot4.fill(0);
      resumeResult4?.readKey.fill(0);
      clearCapturedReadKeys();
    }
  }, 120_000);
});
