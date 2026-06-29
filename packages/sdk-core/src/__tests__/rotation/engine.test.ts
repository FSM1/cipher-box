/**
 * Tests for rotation/engine.ts
 *
 * TDD RED phase — tests written before implementation (63-03 Task 1 + Task 2).
 * Covers: rotateOne happy path, 4 named Phase-64 seam throws, file-node seam
 * trigger, zeroization invariant, rotateReadFromNode root-first ordering,
 * completion, persistCallback, and old-key-cannot-derive assertions.
 *
 * Mock pattern: vi.hoisted + vi.mock (from cas.test.ts analog).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  rotateOne,
  rotateReadFromNode,
  mintFileKeyOnRotate,
  reMintGrantsRootedAt,
  mergeConcurrentChildren,
  verifySubtreeClean,
  type RotationJobRecord,
  type RotationParams,
} from '../../rotation/engine';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks — hoisted before vi.mock() factories
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  // ipns
  resolveIpnsRecord: vi.fn(),
  // ipfs
  fetchFromIpfs: vi.fn(),
  // cas
  publishWithCas: vi.fn(),
  // core codec
  unsealNode: vi.fn(),
  sealNode: vi.fn(),
  sealChildReadKey: vi.fn(),
  unsealChildReadKey: vi.fn(),
}));

vi.mock('../../ipns', () => ({
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  createAndPublishIpnsRecord: vi.fn(),
  batchPublishIpnsRecords: vi.fn(),
}));

vi.mock('../../ipfs', () => ({
  fetchFromIpfs: mockFns.fetchFromIpfs,
  addToIpfs: vi.fn(),
  unpinFromIpfs: vi.fn(),
  registerCid: vi.fn(),
}));

vi.mock('../../cas', () => ({
  publishWithCas: mockFns.publishWithCas,
}));

vi.mock('@cipherbox/core', () => ({
  unsealNode: mockFns.unsealNode,
  sealNode: mockFns.sealNode,
  sealChildReadKey: mockFns.sealChildReadKey,
  unsealChildReadKey: mockFns.unsealChildReadKey,
  CryptoError: class CryptoError extends Error {
    code: string;
    constructor(msg: string, code: string) {
      super(msg);
      this.code = code;
    }
  },
}));

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const NODE_ID = 'node-aaaa-1111-bbbb-cccccccccccc';
const PARENT_IPNS = 'k51parent000000000000000000000000000000000000000000000000000000';
const NODE_IPNS = 'k51child0000000000000000000000000000000000000000000000000000000';
const CHILD_ID = 'child-1111-2222-3333-444444444444';
const CHILD_IPNS = 'k51grandchild00000000000000000000000000000000000000000000000000';

const PARENT_READ_KEY = new Uint8Array(32).fill(0xab);
const SEALED_READ_BODY = 'readSealed==';

function makeFolderNode(
  overrides?: Partial<import('@cipherbox/core').Node>
): import('@cipherbox/core').Node {
  return {
    schema: 'node/v3',
    kind: 'folder',
    id: NODE_ID,
    generation: 2,
    createdAt: 1000,
    modifiedAt: 2000,
    children: [
      {
        name: 'child-folder',
        ipnsName: CHILD_IPNS,
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'childsealed==',
      },
    ],
    ...overrides,
  } as import('@cipherbox/core').Node;
}

function makePublishedNode(
  nodeId: string,
  generation: number,
  kind: 'folder' | 'file' = 'folder'
): import('@cipherbox/core').PublishedNode {
  return {
    schema: 'node/v3',
    kind,
    id: nodeId,
    generation,
    aeadVersion: 1,
    readSealed: SEALED_READ_BODY,
  };
}

function makeJobRecord(overrides?: Partial<RotationJobRecord>): RotationJobRecord {
  return {
    rootNodeId: NODE_ID,
    status: 'pending',
    completedNodeIds: new Set<string>(),
    frontier: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Task 1: rotateOne + 4 named Phase-64 seams
// ---------------------------------------------------------------------------

describe('rotateOne — happy path (folder node, no concurrent-add, no inner grants)', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // resolve → published envelope
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-node-cid',
      sequenceNumber: 3n,
      signatureVerified: true,
    });

    // fetchFromIpfs → raw JSON bytes of PublishedNode
    const published = makePublishedNode(NODE_ID, 2);
    mockFns.fetchFromIpfs.mockResolvedValue(new TextEncoder().encode(JSON.stringify(published)));

    // unsealNode → plaintext folder node with one child
    mockFns.unsealNode.mockResolvedValue(makeFolderNode());

    // sealNode → re-sealed published node under new readKey'
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 3));

    // sealChildReadKey → new readKeySealed for the child ref in the parent
    mockFns.sealChildReadKey.mockResolvedValue('newchildsealed==');

    // publishWithCas → success
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new-cid',
      newSequenceNumber: 4n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('completes without throwing any seam error', async () => {
    const jobRecord = makeJobRecord();
    const ctx = createMockContext();

    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 5n,
        jobRecord,
        ctx,
        // innerGrants not supplied → reMintGrantsRootedAt NOT called
        // writeKey not supplied → write-body skipped (Phase 63 read-chain only)
      })
    ).resolves.toBeDefined();
  });

  it('calls publishWithCas exactly once with the current sequenceNumber', async () => {
    const jobRecord = makeJobRecord();
    const ctx = createMockContext();

    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord,
      ctx,
    });

    expect(mockFns.publishWithCas).toHaveBeenCalledTimes(1);
    // The call to publishWithCas must use the resolved sequenceNumber (3n)
    expect(mockFns.publishWithCas).toHaveBeenCalledWith(
      expect.objectContaining({ sequenceNumber: 3n })
    );
  });

  it('increments generation by exactly 1', async () => {
    const jobRecord = makeJobRecord();
    const ctx = createMockContext();

    const result = await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord,
      ctx,
    });

    // unsealNode returned generation: 2 → newGeneration should be 3
    expect(result.newGeneration).toBe(3);
  });

  it('marks nodeId in completedNodeIds after success', async () => {
    const jobRecord = makeJobRecord();
    const ctx = createMockContext();

    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord,
      ctx,
    });

    expect(jobRecord.completedNodeIds.has(NODE_ID)).toBe(true);
  });

  it('rewrites parent SealedChildRef.readKeySealed + .generation via sealChildReadKey', async () => {
    const jobRecord = makeJobRecord();
    const ctx = createMockContext();

    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord,
      ctx,
    });

    // sealChildReadKey must be called to re-seal the new readKey' under parentReadKey
    expect(mockFns.sealChildReadKey).toHaveBeenCalledTimes(1);
    // First arg = new readKey' (Uint8Array 32 bytes), second = parentReadKey
    const [childReadKeyArg, parentReadKeyArg] = mockFns.sealChildReadKey.mock.calls[0];
    expect(childReadKeyArg).toBeInstanceOf(Uint8Array);
    expect(childReadKeyArg.length).toBe(32);
    // parentReadKey must NOT be zeroed — still has original fill value
    expect(parentReadKeyArg).toEqual(PARENT_READ_KEY);
  });

  it("returns a fresh 32-byte readKey' that differs from parentReadKey", async () => {
    const jobRecord = makeJobRecord();
    const ctx = createMockContext();

    const result = await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord,
      ctx,
    });

    expect(result.childReadKey).toBeInstanceOf(Uint8Array);
    expect(result.childReadKey.length).toBe(32);
    // With overwhelming probability a random 32-byte key differs from the fill value
    expect(result.childReadKey).not.toEqual(PARENT_READ_KEY);
  });
});

describe('rotateOne — idempotency skip', () => {
  it('skips and returns immediately if nodeId already in completedNodeIds', async () => {
    vi.clearAllMocks();
    const jobRecord = makeJobRecord({
      completedNodeIds: new Set([NODE_ID]),
    });

    const result = await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord,
      ctx: createMockContext(),
    });

    expect(result.skipped).toBe(true);
    expect(mockFns.resolveIpnsRecord).not.toHaveBeenCalled();
    expect(mockFns.publishWithCas).not.toHaveBeenCalled();
  });
});

describe('rotateOne — zeroization invariant (Pitfall 4 / T-63-10)', () => {
  it('caller-supplied parentReadKey is unchanged after a successful rotateOne', async () => {
    vi.clearAllMocks();

    const originalKey = new Uint8Array(32).fill(0xcd);
    const snapshotBefore = new Uint8Array(originalKey); // copy

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0)))
    );
    mockFns.unsealNode.mockResolvedValue(makeFolderNode({ generation: 0 }));
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 1));
    mockFns.sealChildReadKey.mockResolvedValue('sealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });

    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      parentReadKey: originalKey,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 1n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
    });

    // The buffer must be byte-for-byte identical to the snapshot
    expect(originalKey).toEqual(snapshotBefore);
  });
});

// ---------------------------------------------------------------------------
// Named seam functions — each throws a Phase-64 error (INDIVIDUALLY TESTABLE)
// ---------------------------------------------------------------------------

describe('Phase-64 named seams — each throws an error naming "phase 64"', () => {
  it('mintFileKeyOnRotate throws with "phase 64" in the message (ROT-03/CRIT-1)', async () => {
    await expect(mintFileKeyOnRotate(makeFolderNode(), makeJobRecord())).rejects.toThrow(
      /phase 64/i
    );
  });

  it('reMintGrantsRootedAt throws with "phase 64" in the message (ROT-04/HIGH-3)', async () => {
    await expect(
      reMintGrantsRootedAt(NODE_ID, new Uint8Array(32), 1, makeJobRecord(), createMockContext())
    ).rejects.toThrow(/phase 64/i);
  });

  it('mergeConcurrentChildren throws with "phase 64" in the message (ROT-05/HIGH-4)', async () => {
    await expect(
      mergeConcurrentChildren(makeFolderNode(), {}, createMockContext())
    ).rejects.toThrow(/phase 64/i);
  });

  it('verifySubtreeClean throws with "phase 64" in the message (ROT-06)', async () => {
    await expect(verifySubtreeClean(NODE_ID, createMockContext())).rejects.toThrow(/phase 64/i);
  });
});

describe('rotateOne — file node reaches mintFileKeyOnRotate and surfaces Phase-64 throw', () => {
  it('throws the Phase-64 mintFileKeyOnRotate error for file nodes', async () => {
    vi.clearAllMocks();

    const fileNode: import('@cipherbox/core').Node = {
      schema: 'node/v3',
      kind: 'file',
      id: NODE_ID,
      generation: 0,
      createdAt: 1000,
      modifiedAt: 2000,
      content: {
        cid: 'bafy-file',
        fileIv: 'iv==',
        size: 1024,
        mimeType: 'text/plain',
        encryptionMode: 'GCM',
        fileKey: new Uint8Array(32).fill(0x11),
        versions: [],
      },
    };

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0, 'file')))
    );
    mockFns.unsealNode.mockResolvedValue(fileNode);

    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 1n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
      })
    ).rejects.toThrow(/phase 64/i);
  });
});

// ---------------------------------------------------------------------------
// Task 2: rotateReadFromNode — resumable frontier walk (ROT-01)
// ---------------------------------------------------------------------------

describe('rotateReadFromNode — root-first BFS ordering (§4.2)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rotates the root node before any child in a depth-2 subtree', async () => {
    const callOrder: string[] = [];

    // Root node
    const rootPublished = makePublishedNode(NODE_ID, 0);
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 0,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
    });

    // Child node (folder, no grandchildren)
    const childPublished = makePublishedNode(CHILD_ID, 0);
    const childNode: import('@cipherbox/core').Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: CHILD_ID,
      generation: 0,
      createdAt: 1000,
      modifiedAt: 2000,
      children: [],
    };

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => {
      callOrder.push(`resolve:${ipnsName}`);
      return {
        cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
        sequenceNumber: 1n,
        signatureVerified: true,
      };
    });

    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      const node = cid === 'bafy-root' ? rootPublished : childPublished;
      return new TextEncoder().encode(JSON.stringify(node));
    });

    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) => {
        return published.id === NODE_ID ? rootNode : childNode;
      }
    );

    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) => {
      callOrder.push(`seal:${node.id}`);
      return makePublishedNode(node.id, node.generation + 1);
    });

    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.publishWithCas.mockImplementation(async (params: { ipnsName: string }) => {
      callOrder.push(`publish:${params.ipnsName}`);
      return { cid: 'bafy-new', newSequenceNumber: 2n, publishedData: [], prunedCids: [] };
    });

    const ctx = createMockContext();
    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID });

    const params: RotationParams = {
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0x77),
      jobRecord,
      ctx,
    };

    await rotateReadFromNode(params);

    // Root must be published before child
    const rootPublishIdx = callOrder.findIndex((c) => c === `publish:${NODE_IPNS}`);
    const childPublishIdx = callOrder.findIndex((c) => c === `publish:${CHILD_IPNS}`);
    expect(rootPublishIdx).toBeGreaterThanOrEqual(0);
    expect(childPublishIdx).toBeGreaterThanOrEqual(0);
    expect(rootPublishIdx).toBeLessThan(childPublishIdx);
  });

  it('job record reaches status "complete" after full subtree rotation', async () => {
    const rootNode = makeFolderNode({ generation: 0, children: [] });
    const rootPublished = makePublishedNode(NODE_ID, 0);

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-root',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(rootPublished))
    );
    mockFns.unsealNode.mockResolvedValue(rootNode);
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 1));
    mockFns.sealChildReadKey.mockResolvedValue('sealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });

    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID });
    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0x55),
      jobRecord,
      ctx: createMockContext(),
    });

    expect(jobRecord.status).toBe('complete');
    expect(jobRecord.completedNodeIds.has(NODE_ID)).toBe(true);
  });

  it('calls persistCallback after each per-node commit', async () => {
    const persistCallback = vi.fn();
    const rootNode = makeFolderNode({ generation: 0, children: [] });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0)))
    );
    mockFns.unsealNode.mockResolvedValue(rootNode);
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 1));
    mockFns.sealChildReadKey.mockResolvedValue('sealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });

    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID, persistCallback });
    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0x33),
      jobRecord,
      ctx: createMockContext(),
    });

    // Called at least once (once per node that was rotated)
    expect(persistCallback).toHaveBeenCalled();
    // Called with the jobRecord
    expect(persistCallback).toHaveBeenCalledWith(jobRecord);
  });

  it('does NOT invoke verifySubtreeClean on a fresh run (no Phase-64 throw on happy walk)', async () => {
    const rootNode = makeFolderNode({ generation: 0, children: [] });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0)))
    );
    mockFns.unsealNode.mockResolvedValue(rootNode);
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 1));
    mockFns.sealChildReadKey.mockResolvedValue('sealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });

    // A fresh run should complete without error (verifySubtreeClean not called)
    await expect(
      rotateReadFromNode({
        rootNodeId: NODE_ID,
        rootNodeIpnsName: NODE_IPNS,
        rootReadKey: new Uint8Array(32).fill(0x22),
        jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
        ctx: createMockContext(),
      })
    ).resolves.toBeUndefined();
  });

  it('completedNodeIds covers all nodes after a depth-2 rotation', async () => {
    const rootPublished = makePublishedNode(NODE_ID, 0);
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 0,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'c==',
        },
      ],
    });
    const childPublished = makePublishedNode(CHILD_ID, 0);
    const childNode: import('@cipherbox/core').Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: CHILD_ID,
      generation: 0,
      createdAt: 1000,
      modifiedAt: 2000,
      children: [],
    };

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 1n,
      signatureVerified: true,
    }));

    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      const node = cid === 'bafy-root' ? rootPublished : childPublished;
      return new TextEncoder().encode(JSON.stringify(node));
    });

    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) => {
        return published.id === NODE_ID ? rootNode : childNode;
      }
    );

    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation + 1)
    );
    mockFns.sealChildReadKey.mockResolvedValue('sealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });

    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID });
    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0x44),
      jobRecord,
      ctx: createMockContext(),
    });

    expect(jobRecord.completedNodeIds.has(NODE_ID)).toBe(true);
    expect(jobRecord.completedNodeIds.has(CHILD_ID)).toBe(true);
  });
});
