/**
 * Read-chain navigation + root-step rotation happy-path sdk-e2e round-trip (D-04).
 *
 * Exercises the Phase-63 read-chain and rotation engine over real IPNS publish/resolve:
 *   issue grant → navigate to file → root-step rotate → revoked grant cannot navigate
 *
 * This is the only Phase-63 real client→API IPNS round-trip gate. It proves the engine
 * survives real IPNS publish/resolve (unit mocks hide first-publish-seq / CAS / zeroization
 * regressions — project memory: sdk-e2e is the cross-package publish gate).
 *
 * Phase-64 note (expected behavior, NOT a failure):
 *   rotateReadFromNode rotates the scope-root FIRST (§4.2 — the revocation cut), then
 *   enters the BFS tail to rotate child nodes. The file child hits the Phase-64
 *   mintFileKeyOnRotate stub and throws. The test catches this expected throw:
 *   the root-step cut IS committed to IPNS; the revocation IS effective.
 *   The crash-safety / fault-injection matrix (TEST-01) is Phase 64.
 *
 * Phase-65 note:
 *   client.uploadFile → createFileMetadata is a Phase-65 stub. This test manually
 *   creates and publishes the file node (kind='file') using sdk-core primitives:
 *   sealNode → addToIpfs → createAndPublishIpnsRecord → addFilePointerToFolder.
 *   This is schema-agnostic per D-05: the API stores opaque IPNS bytes; no shares
 *   table persistence is exercised here.
 *
 * Prerequisites: live local stack
 *   docker compose -f docker/docker-compose.yml up -d
 *   pnpm --filter @cipherbox/api dev   (redis on 6380)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  createSubfolder,
  addFilePointerToFolder,
  updateFolderMetadataAndPublish,
  addToIpfs,
  createAndPublishIpnsRecord,
  navigateReadChain,
  issueReadGrant,
  rotateReadFromNode,
  type RotationJobRecord,
} from '@cipherbox/sdk-core';
import { sealNode } from '@cipherbox/core';
import type { Node } from '@cipherbox/core';
import {
  generateEd25519Keypair,
  deriveEd25519PublicKey,
  deriveIpnsName,
  generateRandomBytes,
} from '@cipherbox/crypto';
import { createMultiAccountFixture, type MultiAccountFixture } from '../fixtures/multi-account';

describe('Read-chain navigation + root-step rotation happy-path round-trip (D-04)', () => {
  let fixture: MultiAccountFixture;

  beforeAll(async () => {
    fixture = await createMultiAccountFixture(['alice', 'bob']);
  });

  afterAll(async () => {
    if (fixture) await fixture.cleanupAll();
  });

  it('issue grant → navigate to file → root-step rotate → revoked grant cannot navigate', async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;
    const aliceCtx = alice.client.getContext();
    const bobCtx = bob.client.getContext();

    // -----------------------------------------------------------------------
    // Step 1: Alice creates the share-root folder via createSubfolder (sdk-core).
    //
    // createSubfolder generates a fresh Ed25519 IPNS keypair, generates a 32-byte
    // readKey and writeKey, seals the empty folder Node, uploads to IPFS, and
    // publishes the first IPNS record at sequenceNumber 1n (Phase-60 strict gate).
    // -----------------------------------------------------------------------
    const folderResult = await createSubfolder({
      name: 'share-root',
      ctx: aliceCtx,
    });

    // Derive the folder's IPNS name from the generated Ed25519 private key.
    const folderIpnsPublicKey = deriveEd25519PublicKey(folderResult.ipnsPrivateKey);
    const folderIpnsName = await deriveIpnsName(folderIpnsPublicKey);

    const folderNodeId = folderResult.node.id;
    const folderGeneration = folderResult.node.generation; // 0

    // -----------------------------------------------------------------------
    // Step 2: Manually create and publish a file node into the folder.
    //
    // client.uploadFile → createFileMetadata is a Phase-65 stub. We bypass it
    // by building the file node directly with sdk-core + @cipherbox/core primitives.
    //
    // The file node's content descriptor (cid, fileKey, etc.) is stored inside the
    // sealed read-body. navigateReadChain unseals it and returns it — it does NOT
    // fetch/decrypt the actual encrypted content bytes. So the cid can be any
    // truthy placeholder for Phase-63 E2E purposes (D-05: schema-agnostic).
    //
    // Steps:
    //   a. Generate a fresh Ed25519 IPNS keypair for the file node.
    //   b. Derive the file node's IPNS name.
    //   c. Generate a 32-byte fileReadKey for the file node.
    //   d. Build the file Node with a placeholder CID in its content descriptor.
    //   e. Seal the file Node with sealNode(node, fileReadKey, dummyWriteKey).
    //   f. Upload the sealed PublishedNode JSON to IPFS.
    //   g. Publish the IPFS CID to the file's IPNS name (seq 1n — first publish).
    //   h. Add the file as a SealedChildRef in the folder via addFilePointerToFolder.
    //   i. Update the folder via updateFolderMetadataAndPublish (CAS, seq 1n→2n).
    // -----------------------------------------------------------------------

    // a. Generate file node's IPNS keypair
    const fileIpnsKeypair = generateEd25519Keypair();
    const fileIpnsName = await deriveIpnsName(fileIpnsKeypair.publicKey);

    // b. Generate 32-byte fileReadKey (the symmetric key for the file node's read-body)
    const fileReadKey = generateRandomBytes(32);
    const dummyWriteKey = new Uint8Array(32); // write-body unused in Phase-63 read-chain

    // c. Build the file Node (kind='file', with content descriptor)
    const fileNodeId = crypto.randomUUID();
    const PLACEHOLDER_CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'; // well-formed CIDv1
    const fileNode: Node = {
      schema: 'node/v3',
      kind: 'file',
      id: fileNodeId,
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

    // d. Seal the file node with sealNode
    const publishedFileNode = await sealNode(fileNode, fileReadKey, dummyWriteKey);

    // e. Upload the sealed file node to IPFS
    const { cid: fileNodeIpfsCid } = await addToIpfs(
      aliceCtx,
      new TextEncoder().encode(JSON.stringify(publishedFileNode))
    );

    // f. Publish the file node to its IPNS name (first publish → seq 1n)
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: fileIpnsKeypair.privateKey,
      ipnsPublicKey: fileIpnsKeypair.publicKey,
      ipnsName: fileIpnsName,
      metadataCid: fileNodeIpfsCid,
      sequenceNumber: 1n,
      ctx: aliceCtx,
    });

    // g. Add the file as a SealedChildRef in the folder (seal fileReadKey under folderReadKey)
    const { updatedChildren } = await addFilePointerToFolder({
      children: [], // folder starts empty (createSubfolder published empty children)
      childReadKey: fileReadKey,
      parentReadKey: folderResult.rootReadKey,
      childId: fileNodeId,
      childKind: 'file',
      childGeneration: 0,
      name: 'shared.txt',
      ipnsName: fileIpnsName,
      versionFloor: 0n,
    });

    // h. Publish the updated folder (adds the file SealedChildRef, seq 1n→2n).
    //    Pass nodeId and nodeGeneration so the sealed body AAD matches createSubfolder.
    await updateFolderMetadataAndPublish({
      children: updatedChildren,
      readKey: folderResult.rootReadKey,
      ipnsPrivateKey: folderResult.ipnsPrivateKey,
      ipnsPublicKey: folderIpnsPublicKey,
      ipnsName: folderIpnsName,
      sequenceNumber: 1n,
      nodeId: folderNodeId,
      nodeGeneration: folderGeneration,
      ctx: aliceCtx,
    });

    // -----------------------------------------------------------------------
    // Step 3: Alice issues a read grant for the folder root to Bob (READ-01).
    //
    // issueReadGrant: ONE ECIES wrap of the share-root readKey → encryptedReadKey.
    // Zero node resolves, zero seal/unseal, zero IPNS publishes (READ-01 / §3.2).
    //
    // Transport-decoupled seam (D-05): Phase 66 wires real shares persistence;
    // here an in-memory stub returns a synthetic shareId (schema-agnostic — D-05).
    // -----------------------------------------------------------------------
    const { encryptedReadKey } = await issueReadGrant({
      shareRootReadKey: folderResult.rootReadKey,
      recipientPublicKey: bob.publicKey,
      rootNodeId: folderNodeId,
      shareRootIpnsName: folderIpnsName,
      rootGeneration: folderGeneration,
      insertShareFn: async (_payload) => ({ shareId: crypto.randomUUID() }),
    });

    // -----------------------------------------------------------------------
    // Step 4: Bob navigates the read chain to the file (pre-rotation).
    //
    // navigateReadChain:
    //   1. ONE ECIES unwrap of encryptedReadKey → shareRootReadKey
    //   2. Resolve root IPNS → fetch PublishedNode (generation == 0)
    //   3. Behind-retry check: 0 > 0 == false → continue
    //   4. Unseal root node
    //   5. Walk path [fileIpnsName]:
    //      a. Find SealedChildRef with ipnsName == fileIpnsName
    //      b. Fetch file's PublishedNode
    //      c. unsealChildReadKey(childRef.readKeySealed, folderReadKey, fileNode.id, 'file', 0)
    //      d. unsealNode(filePublished, fileReadKey) → fileNode
    //   6. Leaf is 'file' kind with content → { status: 'ok', content, nodeId }
    // -----------------------------------------------------------------------
    const preResult = await navigateReadChain({
      encryptedReadKey,
      recipientPrivKey: bob.privateKey,
      shareRootIpnsName: folderIpnsName,
      rootExpectedGeneration: folderGeneration,
      path: [fileIpnsName],
      ctx: bobCtx,
    });

    // Pre-rotation: grant is valid, content key and CID must be present (D-04).
    expect(preResult.status).toBe('ok');
    if (preResult.status === 'ok') {
      expect(preResult.content.cid).toBeTruthy();
      expect(preResult.content.fileKey).toBeInstanceOf(Uint8Array);
      expect(preResult.content.fileKey.length).toBe(32);
    }

    // -----------------------------------------------------------------------
    // Step 5: Alice performs the root-step rotation (rotateReadFromNode).
    //
    // rotateReadFromNode rotates the scope-root FIRST (§4.2 — the revocation cut):
    //   rotateOne(root): resolve → unseal → mint readKey' → re-seal → publishWithCas
    //
    // After the root commit, the root generation advances from 0 to 1. Any
    // pre-rotation grant with rootExpectedGeneration=0 will see generation 1 > 0
    // and navigateReadChain returns 'behind-retry'.
    //
    // After the root commit, rotateReadFromNode enters the BFS tail to process the
    // file child. rotateOne → node.kind === 'file' → mintFileKeyOnRotate (Phase-64
    // seam) throws. This is EXPECTED in Phase 63 — the root cut IS committed.
    // The test catches this throw and verifies the error is the Phase-64 stub.
    // -----------------------------------------------------------------------
    const jobRecord: RotationJobRecord = {
      rootNodeId: folderNodeId,
      status: 'pending',
      completedNodeIds: new Set(),
      frontier: [],
    };

    let rotationError: unknown;
    try {
      await rotateReadFromNode({
        rootNodeId: folderNodeId,
        rootNodeIpnsName: folderIpnsName,
        rootReadKey: folderResult.rootReadKey,
        rootIpnsPrivateKey: folderResult.ipnsPrivateKey,
        rootIpnsPublicKey: folderIpnsPublicKey,
        jobRecord,
        ctx: aliceCtx,
      });
    } catch (err) {
      rotationError = err;
    }

    // The root node must have committed before the Phase-64 stub fired (§4.2).
    expect(jobRecord.completedNodeIds.has(folderNodeId)).toBe(true);

    // The BFS tail must reach the file child's Phase-64 stub and throw.
    // rotateReadFromNode rotates the root then hits mintFileKeyOnRotate's Phase-64
    // stub on the file child — the test captures that error as rotationError.
    expect(rotationError).toBeDefined();
    expect((rotationError as Error).message).toMatch(/phase 64/i);

    // -----------------------------------------------------------------------
    // Step 6: Bob's pre-rotation grant can no longer navigate (revocation cut).
    //
    // After the root-step rotation:
    //   - Root node's published generation == 1 (rotated from 0)
    //   - rootExpectedGeneration from grant issuance == 0
    //   - navigateReadChain Step 3: generation (1) > rootExpectedGeneration (0)
    //     → { status: 'behind-retry' } (NOT 'ok')
    //
    // The same encryptedReadKey (pre-rotation ECIES wrap) is used — it wraps the
    // OLD shareRootReadKey under Bob's public key, which no longer matches the
    // rotated root readKey'.
    // -----------------------------------------------------------------------
    const postResult = await navigateReadChain({
      encryptedReadKey, // same pre-rotation grant encrypted key
      recipientPrivKey: bob.privateKey,
      shareRootIpnsName: folderIpnsName,
      rootExpectedGeneration: folderGeneration, // still 0 — anchored at grant issuance
      path: [fileIpnsName],
      ctx: bobCtx,
    });

    // Post-rotation: the pre-rotation grant must be 'behind-retry' (D-04 / T-63-24).
    // Root generation advanced from 0 to 1; rootExpectedGeneration=0 → generation(1) > 0
    // → navigateReadChain Step 3 returns 'behind-retry' (NOT 'revoked' or 'ok').
    expect(postResult.status).toBe('behind-retry');
  }, 120_000); // 2-minute timeout: live IPNS round-trips involve multiple publish/resolve cycles
});
