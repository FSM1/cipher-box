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
  verifySubtreeClean,
  mergeConcurrentChildren,
  RootKeyStaleError,
  type GrantRemintCallbacks,
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

  // Fake non-zero key for tests (publishWithCas is mocked — key value is unused at runtime).
  const FAKE_NODE_KEY = new Uint8Array(32).fill(0x11);

  it('completes without throwing any seam error', async () => {
    const jobRecord = makeJobRecord();
    const ctx = createMockContext();

    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: FAKE_NODE_KEY, // D-01 fail-closed requires a key
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
      nodeIpnsPrivateKey: FAKE_NODE_KEY,
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
      nodeIpnsPrivateKey: FAKE_NODE_KEY,
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
      nodeIpnsPrivateKey: FAKE_NODE_KEY,
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
      nodeIpnsPrivateKey: FAKE_NODE_KEY,
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
      nodeIpnsPrivateKey: FAKE_NODE_KEY,
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
      nodeIpnsPrivateKey: new Uint8Array(32).fill(0x11), // D-01 fail-closed requires a key
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
  it('reMintGrantsRootedAt is a no-op when no callbacks supplied (seam filled in Phase 64)', async () => {
    // Phase 64 fills this seam: calling without callbacks is a clean no-op (D-04).
    // Full behavior is tested in grant-remint.test.ts (ROT-04/HIGH-3/D-04).
    await expect(
      reMintGrantsRootedAt(NODE_ID, new Uint8Array(32), 1, makeJobRecord(), createMockContext())
    ).resolves.toBeUndefined();
  });

  // verifySubtreeClean now returns { isDirty, frontier } — tested in Plan 64-07 suite below.
});

// Note: The Phase-63 'throws the Phase-64 mintFileKeyOnRotate error for file nodes' test
// was removed in plan 64-03 GREEN phase — mintFileKeyOnRotate is now filled and no longer throws.

// ---------------------------------------------------------------------------
// Task 2: rotateReadFromNode — resumable frontier walk (ROT-01)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Plan 64-03 RED tests — content-key rotation (ROT-03/CRIT-1)
// ---------------------------------------------------------------------------

describe('mintFileKeyOnRotate — content-key rotation (ROT-03/CRIT-1)', () => {
  it('assigns a fresh 32-byte fileKey to the node content, different from the old key', async () => {
    const oldKey = new Uint8Array(32).fill(0x11);
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
        fileKey: new Uint8Array(oldKey),
        versions: [],
      },
    };

    await mintFileKeyOnRotate(fileNode, makeJobRecord());

    // Must have been assigned a new value
    expect(fileNode.content!.fileKey).toBeInstanceOf(Uint8Array);
    expect(fileNode.content!.fileKey.length).toBe(32);
    // Must differ from the original key
    expect(fileNode.content!.fileKey).not.toEqual(oldKey);
  });

  it('is a no-op for nodes without content (folder nodes) — no throw, no content field added', async () => {
    const folderNode = makeFolderNode();
    // Ensure no content field
    expect((folderNode as Record<string, unknown>)['content']).toBeUndefined();

    await expect(mintFileKeyOnRotate(folderNode, makeJobRecord())).resolves.toBeUndefined();

    // No content field should have been added
    expect((folderNode as Record<string, unknown>)['content']).toBeUndefined();
  });
});

describe('rotateOne — file node with mintFileKeyOnRotate filled (ROT-03 integration)', () => {
  it('sealNode receives the new fileKey after mintFileKeyOnRotate (§7.3 test 2 shape)', async () => {
    vi.clearAllMocks();

    const oldKey = new Uint8Array(32).fill(0x11);
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
        fileKey: new Uint8Array(oldKey),
        versions: [],
      },
    };

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-file-cid',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0, 'file')))
    );
    mockFns.unsealNode.mockResolvedValue(fileNode);

    let sealNodeCalledWithNode: import('@cipherbox/core').Node | undefined;
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) => {
      sealNodeCalledWithNode = node;
      return makePublishedNode(node.id, node.generation + 1, 'file');
    });

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
      nodeIpnsPrivateKey: new Uint8Array(32).fill(0x11), // D-01 fail-closed requires a key
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 1n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
    });

    // sealNode must have been called after mintFileKeyOnRotate mutated the node
    expect(sealNodeCalledWithNode).toBeDefined();
    expect(sealNodeCalledWithNode!.content!.fileKey).toBeInstanceOf(Uint8Array);
    // The fileKey handed to sealNode must differ from the pre-rotation key
    expect(sealNodeCalledWithNode!.content!.fileKey).not.toEqual(oldKey);
  });
});

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
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
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
      rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY,
      nodeKeySource: (ipnsName: string) =>
        ipnsName === CHILD_IPNS
          ? { privateKey: TASK1_CHILD_IPNS_PRIVATE_KEY, publicKey: TASK1_STUB_PUBLIC_KEY }
          : undefined,
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
      rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY, // D-01 fail-closed requires a key
      jobRecord,
      ctx: createMockContext(),
    });

    expect(jobRecord.status).toBe('complete');
    expect(jobRecord.completedNodeIds.has(NODE_ID)).toBe(true);
  });

  it('returns the root RotateReadResult (readKey/generation/sequenceNumber) on a fresh rotation (Gap 2)', async () => {
    // Analog of "job record reaches status complete": a fresh, single-node
    // (no children) rotation. Asserts rotateReadFromNode's return value
    // matches the root's own rotateOne result instead of discarding it.
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

    // rotateOne mints readKeyPrime via the REAL crypto.getRandomValues (not mocked
    // by this suite) — spy on it to capture the exact bytes minted for the root so
    // the assertion below proves equality-by-value, not just shape.
    let mintedRootReadKey: Uint8Array | undefined;
    const getRandomValuesSpy = vi
      .spyOn(globalThis.crypto, 'getRandomValues')
      .mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
        const bytes = array as unknown as Uint8Array;
        bytes.fill(0x99);
        mintedRootReadKey = new Uint8Array(bytes);
        return array;
      });

    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID });
    let result;
    try {
      result = await rotateReadFromNode({
        rootNodeId: NODE_ID,
        rootNodeIpnsName: NODE_IPNS,
        rootReadKey: new Uint8Array(32).fill(0x55),
        rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY, // D-01 fail-closed requires a key
        jobRecord,
        ctx: createMockContext(),
      });
    } finally {
      getRandomValuesSpy.mockRestore();
    }

    expect(result).toBeDefined();
    expect(result?.readKey).toEqual(mintedRootReadKey);
    expect(result?.generation).toBe(1);
    expect(result?.sequenceNumber).toBe(2n);
  });

  it('returns undefined on the clean resume/skip path (root already committed in a prior run, Gap 2)', async () => {
    // Analog of Test 4 ("clean resume") below: root already in completedNodeIds
    // (rotateOne's fast-path idempotency skip returns { skipped: true }), and
    // verifySubtreeClean reports no dirty edges — the early-return resume path.
    // There is no fresh root key minted this run, so the return must be undefined.
    const rootNode = makeFolderNode({ generation: 1, children: [] });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-root',
      sequenceNumber: 2n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 1)))
    );
    mockFns.unsealNode.mockResolvedValue(rootNode);

    const jobRecord = makeJobRecord({
      rootNodeId: NODE_ID,
      completedNodeIds: new Set([NODE_ID]),
    });

    const result = await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0x77),
      jobRecord,
      ctx: createMockContext(),
    });

    expect(result).toBeUndefined();
    expect(jobRecord.status).toBe('complete');
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
      rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY, // D-01 fail-closed requires a key
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

    // A fresh run should complete without error (verifySubtreeClean not called).
    // Gap 2: a fresh (non-skip) rotation now resolves to a defined RotateReadResult
    // (was `undefined`/void pre-68-12) — this assertion tracks that additive change.
    await expect(
      rotateReadFromNode({
        rootNodeId: NODE_ID,
        rootNodeIpnsName: NODE_IPNS,
        rootReadKey: new Uint8Array(32).fill(0x22),
        rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY, // D-01 fail-closed requires a key
        jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
        ctx: createMockContext(),
      })
    ).resolves.toBeDefined();
  });

  it('completedNodeIds covers all nodes after a depth-2 rotation (root → child)', async () => {
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
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
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
      rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY, // D-01 fail-closed requires a key
      nodeKeySource: (ipnsName: string) =>
        ipnsName === CHILD_IPNS
          ? { privateKey: TASK1_CHILD_IPNS_PRIVATE_KEY, publicKey: TASK1_STUB_PUBLIC_KEY }
          : undefined,
      jobRecord,
      ctx: createMockContext(),
    });

    expect(jobRecord.completedNodeIds.has(NODE_ID)).toBe(true);
    expect(jobRecord.completedNodeIds.has(CHILD_ID)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Plan 64-04 Task 1 RED — D-01 fail-closed + nodeKeySource
// ---------------------------------------------------------------------------

const TASK1_ROOT_IPNS_PRIVATE_KEY = new Uint8Array(32).fill(0x10);
const TASK1_CHILD_IPNS_PRIVATE_KEY = new Uint8Array(32).fill(0x12);
const TASK1_STUB_PUBLIC_KEY = new Uint8Array(32).fill(0x01);

describe('D-01 fail-closed: rotateOne requires a real nodeIpnsPrivateKey (Plan 64-04)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-node-cid',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0)))
    );
    mockFns.unsealNode.mockResolvedValue(makeFolderNode({ generation: 0, children: [] }));
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 1));
    mockFns.sealChildReadKey.mockResolvedValue('sealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('throws when nodeIpnsPrivateKey is absent (D-01 fail-closed)', async () => {
    // RED: rotateOne currently does NOT throw when key is absent (uses placeholder).
    // GREEN: after adding the guard, this rejects with /no IPNS private key/.
    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: undefined,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 1n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
      })
    ).rejects.toThrow(/no valid IPNS private key/i);
  });

  it('does not call publishWithCas with an all-zero placeholder key when nodeIpnsPrivateKey absent', async () => {
    // RED: buggy Phase-63 code calls publishWithCas with PLACEHOLDER_WRITE_KEY (32 zeros).
    // GREEN: the guard throws before publishWithCas is reached.
    // Assertion: no publishWithCas call with an all-zero ipnsPrivateKey.
    try {
      await rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: undefined,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 1n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
      });
    } catch {
      // Expected to throw after GREEN fix; in RED it resolves.
    }
    const calledWithZeroKey = mockFns.publishWithCas.mock.calls.some((callArgs: unknown[]) => {
      const p = callArgs[0] as { ipnsPrivateKey?: Uint8Array };
      return p.ipnsPrivateKey instanceof Uint8Array && p.ipnsPrivateKey.every((b) => b === 0);
    });
    // In RED: calledWithZeroKey === true (buggy placeholder) → assertion fails
    // In GREEN: calledWithZeroKey === false (throw before publish) → assertion passes
    expect(calledWithZeroKey).toBe(false);
  });
});

describe('D-01 nodeKeySource: BFS key threading (Plan 64-04 Task 1)', () => {
  function makeBfsRootChildFixtures() {
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
    const rootPublished = makePublishedNode(NODE_ID, 0);
    const childNode: import('@cipherbox/core').Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: CHILD_ID,
      generation: 0,
      createdAt: 1000,
      modifiedAt: 2000,
      children: [],
    };
    const childPublished = makePublishedNode(CHILD_ID, 0);
    return { rootNode, rootPublished, childNode, childPublished };
  }

  beforeEach(() => {
    vi.clearAllMocks();
    const { rootNode, rootPublished, childNode, childPublished } = makeBfsRootChildFixtures();

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
      async (published: import('@cipherbox/core').PublishedNode) =>
        published.id === NODE_ID ? rootNode : childNode
    );
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation + 1)
    );
    mockFns.sealChildReadKey.mockResolvedValue('sealed==');
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('BFS threads the nodeKeySource key to child rotateOne (not all-zero placeholder)', async () => {
    // RED: child currently gets PLACEHOLDER_WRITE_KEY (all zeros) — nodeKeySource is ignored.
    // GREEN: child gets TASK1_CHILD_IPNS_PRIVATE_KEY from nodeKeySource.
    const capturedPublishKeys: Array<Uint8Array | undefined> = [];
    mockFns.publishWithCas.mockImplementation(async (params: { ipnsPrivateKey?: Uint8Array }) => {
      capturedPublishKeys.push(
        params.ipnsPrivateKey ? new Uint8Array(params.ipnsPrivateKey) : undefined
      );
      return { cid: 'bafy-new', newSequenceNumber: 2n, publishedData: [], prunedCids: [] };
    });

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0x77),
      rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY,
      rootIpnsPublicKey: TASK1_STUB_PUBLIC_KEY,
      nodeKeySource: (ipnsName: string) =>
        ipnsName === CHILD_IPNS
          ? { privateKey: TASK1_CHILD_IPNS_PRIVATE_KEY, publicKey: TASK1_STUB_PUBLIC_KEY }
          : undefined,
      jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
      ctx: createMockContext(),
    });

    // At least 2 publishes: root + child (plus possibly parent re-publish in Task 2)
    expect(capturedPublishKeys.length).toBeGreaterThanOrEqual(2);
    const childPublishKey = capturedPublishKeys[1]; // second publish = child node
    // RED: childPublishKey = all zeros (placeholder) → not equal to TASK1_CHILD_IPNS_PRIVATE_KEY
    // GREEN: childPublishKey = TASK1_CHILD_IPNS_PRIVATE_KEY (from nodeKeySource)
    expect(childPublishKey).toEqual(TASK1_CHILD_IPNS_PRIVATE_KEY);
  });

  it('BFS throws when nodeKeySource returns undefined for a child (D-01 fail-closed)', async () => {
    // RED: rotateReadFromNode resolves without throwing (no guard yet).
    // GREEN: child gets undefined from nodeKeySource → rotateOne throws fail-closed.
    await expect(
      rotateReadFromNode({
        rootNodeId: NODE_ID,
        rootNodeIpnsName: NODE_IPNS,
        rootReadKey: new Uint8Array(32).fill(0x77),
        rootIpnsPrivateKey: TASK1_ROOT_IPNS_PRIVATE_KEY,
        nodeKeySource: (_ipnsName: string) => undefined,
        jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
        ctx: createMockContext(),
      })
    ).rejects.toThrow(/no valid IPNS private key/i);
  });
});

// ---------------------------------------------------------------------------
// Plan 64-04 Task 2 RED — D-02 parent re-seal + D-09 batched parent publish
// ---------------------------------------------------------------------------

const TASK2_ROOT_READ_KEY = new Uint8Array(32).fill(0x77);
const TASK2_ROOT_IPNS_KEY = new Uint8Array(32).fill(0x10);
const TASK2_CHILD_IPNS_KEY = new Uint8Array(32).fill(0x12);
const TASK2_STUB_PUB_KEY = new Uint8Array(32).fill(0x01);

/**
 * Shared fixture builder for the D-02/D-09 BFS tests.
 *
 * Topology: root (NODE_ID, NODE_IPNS) → child (CHILD_ID, CHILD_IPNS)
 *
 * rootNode has one SealedChildRef pointing at CHILD_IPNS.
 * childNode has no children.
 */
function makeD02Fixtures() {
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
  const rootPublished = makePublishedNode(NODE_ID, 0);
  const childNode: import('@cipherbox/core').Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: CHILD_ID,
    generation: 0,
    createdAt: 1000,
    modifiedAt: 2000,
    children: [],
  };
  const childPublished = makePublishedNode(CHILD_ID, 0);
  return { rootNode, rootPublished, childNode, childPublished };
}

// ---------------------------------------------------------------------------
// Plan 64-06 RED — CAS-409 concurrent-add merge (ROT-05/HIGH-4)
// ---------------------------------------------------------------------------

const CONCURRENT_CHILD_IPNS = 'k51concurrent000000000000000000000000000000000000000000000000000';

describe('CAS-409 concurrent-add merge — ROT-05/HIGH-4 (Plan 64-06)', () => {
  const LOCAL_CHILD_REF = {
    name: 'local-child',
    ipnsName: CHILD_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: 'localChildSealed==',
  };
  const CONCURRENT_CHILD_REF = {
    name: 'concurrent-child',
    ipnsName: CONCURRENT_CHILD_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: 'concurrentChildSealed==',
  };

  const FAKE_NODE_KEY_06 = new Uint8Array(32).fill(0x11);

  /** Configures publishWithCas to simulate a CAS-409 by invoking params.merge directly. */
  function setupCas409Mock(
    basePub: import('@cipherbox/core').PublishedNode,
    localPub: import('@cipherbox/core').PublishedNode,
    remotePub: import('@cipherbox/core').PublishedNode
  ) {
    mockFns.publishWithCas.mockImplementation(
      async (params: {
        merge: (
          base: import('@cipherbox/core').PublishedNode | undefined,
          local: import('@cipherbox/core').PublishedNode,
          remote: import('@cipherbox/core').PublishedNode
        ) => unknown;
      }) => {
        const mergeResult = await Promise.resolve(params.merge(basePub, localPub, remotePub));
        const { merged } = mergeResult as { merged: import('@cipherbox/core').PublishedNode };
        return { cid: 'bafy-merged', newSequenceNumber: 4n, publishedData: merged, prunedCids: [] };
      }
    );
  }

  beforeEach(() => {
    // vi.resetAllMocks() clears calls AND drains mockResolvedValueOnce queues,
    // preventing leftover Once-values from failing tests contaminating later tests.
    vi.resetAllMocks();
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-base-cid',
      sequenceNumber: 3n,
      signatureVerified: true,
    });
    const basePub = makePublishedNode(NODE_ID, 2);
    mockFns.fetchFromIpfs.mockResolvedValue(new TextEncoder().encode(JSON.stringify(basePub)));
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
  });

  it('Test 1: concurrent child add survives — merged node includes the remote-only child', async () => {
    const basePub = makePublishedNode(NODE_ID, 2);
    const remotePub = { ...makePublishedNode(NODE_ID, 2), readSealed: 'remoteSealed==' };
    const localPub = makePublishedNode(NODE_ID, 3);

    const localNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const baseNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const remoteNode = makeFolderNode({
      id: NODE_ID,
      generation: 2,
      children: [LOCAL_CHILD_REF, CONCURRENT_CHILD_REF],
    });

    mockFns.unsealNode
      .mockResolvedValueOnce(localNode)
      .mockResolvedValueOnce(baseNode)
      .mockResolvedValueOnce(remoteNode);

    const capturedSealNodes: import('@cipherbox/core').Node[] = [];
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) => {
      capturedSealNodes.push(node);
      return makePublishedNode(node.id, node.generation);
    });

    setupCas409Mock(basePub, localPub, remotePub);

    // RED: throws "not implemented — phase 64" from the merge callback
    // GREEN: resolves; merged node has both local + concurrent children
    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: FAKE_NODE_KEY_06,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 3n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
      })
    ).resolves.toBeDefined();

    const lastSeal = capturedSealNodes[capturedSealNodes.length - 1];
    expect(lastSeal).toBeDefined();
    const childIpnsNames = lastSeal.children?.map((c) => c.ipnsName) ?? [];
    expect(childIpnsNames).toContain(CHILD_IPNS);
    expect(childIpnsNames).toContain(CONCURRENT_CHILD_IPNS);
  });

  it('Test 2: merge re-decodes the REMOTE node — 3 unsealNode calls prove remote was decoded', async () => {
    const basePub = makePublishedNode(NODE_ID, 2);
    const remotePub = { ...makePublishedNode(NODE_ID, 2), readSealed: 'remoteSealed==' };
    const localPub = makePublishedNode(NODE_ID, 3);

    const localNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const baseNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const remoteNode = makeFolderNode({
      id: NODE_ID,
      generation: 2,
      children: [LOCAL_CHILD_REF, CONCURRENT_CHILD_REF],
    });

    mockFns.unsealNode
      .mockResolvedValueOnce(localNode)
      .mockResolvedValueOnce(baseNode)
      .mockResolvedValueOnce(remoteNode);

    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation)
    );

    setupCas409Mock(basePub, localPub, remotePub);

    // RED: throws; GREEN: 3 unsealNode calls (initial + base + remote)
    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: FAKE_NODE_KEY_06,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 3n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
      })
    ).resolves.toBeDefined();

    // 3 calls: initial unseal, unseal(base) in merge callback, unseal(remote) in mergeConcurrentChildren
    expect(mockFns.unsealNode).toHaveBeenCalledTimes(3);
  });

  it('Test 3: merge re-seals under readKey-prime — both sealNode calls share the same (non-old) key', async () => {
    const basePub = makePublishedNode(NODE_ID, 2);
    const remotePub = { ...makePublishedNode(NODE_ID, 2), readSealed: 'remoteSealed==' };
    const localPub = makePublishedNode(NODE_ID, 3);

    const localNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const baseNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const remoteNode = makeFolderNode({
      id: NODE_ID,
      generation: 2,
      children: [LOCAL_CHILD_REF, CONCURRENT_CHILD_REF],
    });

    mockFns.unsealNode
      .mockResolvedValueOnce(localNode)
      .mockResolvedValueOnce(baseNode)
      .mockResolvedValueOnce(remoteNode);

    const capturedSealKeys: Uint8Array[] = [];
    mockFns.sealNode.mockImplementation(
      async (_node: import('@cipherbox/core').Node, key: Uint8Array) => {
        capturedSealKeys.push(new Uint8Array(key));
        return makePublishedNode(_node.id, _node.generation);
      }
    );

    setupCas409Mock(basePub, localPub, remotePub);

    // RED: throws; GREEN: merge re-seal uses readKey' (same as initial seal key, not PARENT_READ_KEY)
    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: FAKE_NODE_KEY_06,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 3n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
      })
    ).resolves.toBeDefined();

    // Two sealNode calls: initial re-seal + merge re-seal
    expect(capturedSealKeys.length).toBeGreaterThanOrEqual(2);

    // Both calls use the same readKey' (minted once in rotateOne)
    const firstKey = capturedSealKeys[0];
    const mergeKey = capturedSealKeys[capturedSealKeys.length - 1];
    expect(mergeKey).toEqual(firstKey);

    // That key must NOT be the old readKey (PARENT_READ_KEY = fill(0xab))
    expect(mergeKey).not.toEqual(PARENT_READ_KEY);
  });

  it('Test 4: happy path — no 409 never invokes the merge callback (unsealNode + sealNode called once each)', async () => {
    const localNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    mockFns.unsealNode.mockResolvedValue(localNode);
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation)
    );

    // Standard happy-path mock: does NOT invoke params.merge
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 4n,
      publishedData: makePublishedNode(NODE_ID, 3),
      prunedCids: [],
    });

    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      nodeIpnsPrivateKey: FAKE_NODE_KEY_06,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 3n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
    });

    // No merge invocation: unsealNode called once (initial fetch), sealNode called once (initial seal)
    expect(mockFns.unsealNode).toHaveBeenCalledTimes(1);
    expect(mockFns.sealNode).toHaveBeenCalledTimes(1);
  });

  it('Test 5 (Plan 70-04): local wins on conflict — merged child keeps the LOCAL (new-key) readKeySealed over remote stale seal', async () => {
    const basePub = makePublishedNode(NODE_ID, 2);
    const remotePub = { ...makePublishedNode(NODE_ID, 2), readSealed: 'remoteSealed==' };
    const localPub = makePublishedNode(NODE_ID, 3);

    // Local carries the rotation's own re-sealed child ref (LOCAL_CHILD_REF, new-key seal).
    const localNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const baseNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    // Remote still holds the SAME child under a stale (pre-rotation) seal — a concurrent
    // writer republished without picking up the rotation's re-seal.
    const REMOTE_STALE_CHILD_REF = { ...LOCAL_CHILD_REF, readKeySealed: 'remoteStaleSealed==' };
    const remoteNode = makeFolderNode({
      id: NODE_ID,
      generation: 2,
      children: [REMOTE_STALE_CHILD_REF],
    });

    mockFns.unsealNode
      .mockResolvedValueOnce(localNode)
      .mockResolvedValueOnce(baseNode)
      .mockResolvedValueOnce(remoteNode);

    const capturedSealNodes: import('@cipherbox/core').Node[] = [];
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) => {
      capturedSealNodes.push(node);
      return makePublishedNode(node.id, node.generation);
    });

    setupCas409Mock(basePub, localPub, remotePub);

    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: FAKE_NODE_KEY_06,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 3n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
      })
    ).resolves.toBeDefined();

    const lastSeal = capturedSealNodes[capturedSealNodes.length - 1];
    const mergedChild = lastSeal.children?.find((c) => c.ipnsName === CHILD_IPNS);
    expect(mergedChild).toBeDefined();
    // Local wins: the merged child keeps LOCAL's readKeySealed, not remote's stale seal.
    expect(mergedChild?.readKeySealed).toBe(LOCAL_CHILD_REF.readKeySealed);
    expect(mergedChild?.readKeySealed).not.toBe(REMOTE_STALE_CHILD_REF.readKeySealed);
  });

  it('Test 6 (Plan 70-04): rotateOne returns the MERGED children (incl. remote add), not the pre-merge node.children snapshot', async () => {
    const basePub = makePublishedNode(NODE_ID, 2);
    const remotePub = { ...makePublishedNode(NODE_ID, 2), readSealed: 'remoteSealed==' };
    const localPub = makePublishedNode(NODE_ID, 3);

    const localNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const baseNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const remoteNode = makeFolderNode({
      id: NODE_ID,
      generation: 2,
      children: [LOCAL_CHILD_REF, CONCURRENT_CHILD_REF],
    });

    mockFns.unsealNode
      .mockResolvedValueOnce(localNode)
      .mockResolvedValueOnce(baseNode)
      .mockResolvedValueOnce(remoteNode);

    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation)
    );

    setupCas409Mock(basePub, localPub, remotePub);

    const result = await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      nodeIpnsPrivateKey: FAKE_NODE_KEY_06,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 3n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
    });

    expect(result.skipped).toBe(false);
    if (!result.skipped) {
      const returnedIpnsNames = result.children.map((c) => c.ipnsName);
      // RED: node.children (pre-merge snapshot) only has LOCAL_CHILD_REF — the
      // concurrently-added remote child is missing from the return.
      // GREEN: rotateOne captures and returns the CAS-merged set.
      expect(returnedIpnsNames).toContain(CONCURRENT_CHILD_IPNS);
      expect(returnedIpnsNames).toContain(CHILD_IPNS);
    }
  });

  it('Test 7 (Plan 70-04): mergeConcurrentChildren returns { published, mergedChildren } reflecting local-wins + concurrent-add merge', async () => {
    const basePub = makePublishedNode(NODE_ID, 2);
    const remotePub = makePublishedNode(NODE_ID, 2);

    const baseNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const remoteNode = makeFolderNode({
      id: NODE_ID,
      generation: 2,
      children: [LOCAL_CHILD_REF, CONCURRENT_CHILD_REF],
    });

    mockFns.unsealNode.mockResolvedValueOnce(baseNode).mockResolvedValueOnce(remoteNode);
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation)
    );

    const localNode = makeFolderNode({ id: NODE_ID, generation: 2, children: [LOCAL_CHILD_REF] });
    const newReadKey = new Uint8Array(32).fill(0x99);
    const writeKey = new Uint8Array(0);

    const result = await mergeConcurrentChildren(
      basePub,
      remotePub,
      PARENT_READ_KEY,
      localNode.children ?? [],
      newReadKey,
      localNode,
      3,
      writeKey
    );

    expect(result).toHaveProperty('published');
    expect(result).toHaveProperty('mergedChildren');
    const mergedIpnsNames = result.mergedChildren.map((c) => c.ipnsName);
    expect(mergedIpnsNames).toContain(CHILD_IPNS);
    expect(mergedIpnsNames).toContain(CONCURRENT_CHILD_IPNS);
  });
});

describe('D-02 parent-link re-seal + D-09 batched parent publish (Plan 64-04 Task 2)', () => {
  /**
   * Capture the readKeyPrime minted by each sealNode call so tests can verify
   * which key was used as the parent's new readKey in the D-02 re-seal.
   */
  const capturedSealNodeReadKeys: Array<Uint8Array> = [];

  beforeEach(() => {
    // vi.resetAllMocks() clears calls AND drains mockResolvedValueOnce queues,
    // preventing leftover Once-values from failing 64-06 RED tests contaminating
    // these tests when the full suite runs. vi.clearAllMocks() was insufficient.
    vi.resetAllMocks();
    capturedSealNodeReadKeys.length = 0;

    const { rootNode, rootPublished, childNode, childPublished } = makeD02Fixtures();

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 3n,
      signatureVerified: true,
    }));

    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      const node = cid === 'bafy-root' ? rootPublished : childPublished;
      return new TextEncoder().encode(JSON.stringify(node));
    });

    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) =>
        published.id === NODE_ID ? rootNode : childNode
    );

    // Capture the readKeyPrime argument (second arg) passed to sealNode per call.
    mockFns.sealNode.mockImplementation(
      async (node: import('@cipherbox/core').Node, readKey: Uint8Array) => {
        capturedSealNodeReadKeys.push(new Uint8Array(readKey));
        return makePublishedNode(node.id, node.generation + 1);
      }
    );

    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 4n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('D-02: sealChildReadKey is called with the parent NEW readKey for the child re-seal', async () => {
    // In RED: the BFS does NOT perform the out-of-band D-02 re-seal, so sealChildReadKey
    // is called only twice (once per rotateOne: root + child). Neither call uses the
    // root's new readKey' as the parent key.
    //
    // In GREEN: a third sealChildReadKey call occurs in rotateReadFromNode AFTER the child
    // rotates, using rootNewReadKey' as the second argument.
    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: TASK2_ROOT_READ_KEY,
      rootIpnsPrivateKey: TASK2_ROOT_IPNS_KEY,
      nodeKeySource: (ipnsName: string) =>
        ipnsName === CHILD_IPNS
          ? { privateKey: TASK2_CHILD_IPNS_KEY, publicKey: TASK2_STUB_PUB_KEY }
          : undefined,
      jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
      ctx: createMockContext(),
    });

    // capturedSealNodeReadKeys[0] = root's new readKeyPrime
    const rootNewReadKey = capturedSealNodeReadKeys[0];
    expect(rootNewReadKey).toBeDefined();
    expect(rootNewReadKey.length).toBe(32);

    // In GREEN: one of the sealChildReadKey calls uses rootNewReadKey as the second arg,
    // the child's id, and the child's new generation (1) to produce the D-02 re-sealed link.
    const sealChildCalls = mockFns.sealChildReadKey.mock.calls;
    const hasD02Call = sealChildCalls.some((callArgs: unknown[]) => {
      const parentKey = callArgs[1] as Uint8Array;
      const id = callArgs[2] as string;
      const gen = callArgs[4] as number;
      return (
        id === CHILD_ID &&
        gen === 1 &&
        parentKey instanceof Uint8Array &&
        parentKey.length === 32 &&
        parentKey.every((b, i) => b === rootNewReadKey[i])
      );
    });
    // RED: hasD02Call === false → FAILS
    // GREEN: hasD02Call === true → PASSES
    expect(hasD02Call).toBe(true);
  });

  it('D-09: parent is republished exactly once after all children rotate (3 publishWithCas calls total)', async () => {
    // In RED: only 2 publishWithCas calls (root + child) — no batched parent republish.
    // In GREEN: 3 calls (root + child + parent re-publish).
    const publishCalls: Array<{ ipnsName: string; sequenceNumber: bigint }> = [];
    mockFns.publishWithCas.mockImplementation(
      async (params: { ipnsName: string; sequenceNumber: bigint }) => {
        publishCalls.push({ ipnsName: params.ipnsName, sequenceNumber: params.sequenceNumber });
        return { cid: 'bafy-new', newSequenceNumber: 4n, publishedData: [], prunedCids: [] };
      }
    );

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: TASK2_ROOT_READ_KEY,
      rootIpnsPrivateKey: TASK2_ROOT_IPNS_KEY,
      nodeKeySource: (ipnsName: string) =>
        ipnsName === CHILD_IPNS
          ? { privateKey: TASK2_CHILD_IPNS_KEY, publicKey: TASK2_STUB_PUB_KEY }
          : undefined,
      jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
      ctx: createMockContext(),
    });

    // RED: publishCalls.length === 2 → FAILS
    // GREEN: publishCalls.length === 3 → PASSES
    expect(publishCalls.length).toBe(3);

    // The third call must be the batched parent re-publish (root IPNS, sequenceNumber = 4n
    // from root's first publish return value).
    const thirdCall = publishCalls[2];
    expect(thirdCall.ipnsName).toBe(NODE_IPNS);
    // The CAS guard for the re-publish must be the sequence returned from root's first publish.
    expect(thirdCall.sequenceNumber).toBe(4n);
  });

  it('D-09: sealChildReadKey total call count is 3 for root→child (2 from rotateOne + 1 D-02 re-seal)', async () => {
    // rotateOne for root:  sealChildReadKey(rootReadKeyPrime, rootOldReadKey,  NODE_ID, kind, 1)
    // rotateOne for child: sealChildReadKey(childReadKeyPrime, childOldReadKey, CHILD_ID, kind, 1)
    // D-02 re-seal:        sealChildReadKey(childReadKeyPrime, rootNewReadKey', CHILD_ID, kind, 1)
    //
    // RED: sealChildReadKey called only 2× (no D-02 re-seal) → FAILS
    // GREEN: called 3× → PASSES
    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: TASK2_ROOT_READ_KEY,
      rootIpnsPrivateKey: TASK2_ROOT_IPNS_KEY,
      nodeKeySource: (ipnsName: string) =>
        ipnsName === CHILD_IPNS
          ? { privateKey: TASK2_CHILD_IPNS_KEY, publicKey: TASK2_STUB_PUB_KEY }
          : undefined,
      jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
      ctx: createMockContext(),
    });

    // RED: 2 calls → FAILS
    // GREEN: 3 calls → PASSES
    expect(mockFns.sealChildReadKey).toHaveBeenCalledTimes(3);
  });
});

// ---------------------------------------------------------------------------
// Plan 64-07 Task 1 RED — verifySubtreeClean + resume guard + convergence guard
// ---------------------------------------------------------------------------

// Shared IPNS key constants for 64-07 Task 1 tests
const T07_ROOT_READ_KEY = new Uint8Array(32).fill(0xcc);
const T07_ROOT_IPNS_KEY = new Uint8Array(32).fill(0x10);
const T07_CHILD_IPNS_KEY = new Uint8Array(32).fill(0x12);
const T07_STUB_PUB_KEY = new Uint8Array(32).fill(0x01);

describe('verifySubtreeClean — BFS dirty-edge frontier (Plan 64-07 ROT-06)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('Test 1: returns { isDirty: false, frontier: [] } when all child generations match', async () => {
    // Root: children[{generation: 1}] (parent mirror = 1), child published at generation 1 → clean
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 1,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 1, // parent mirror matches child's actual generation
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
    });

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 2n,
      signatureVerified: true,
    }));
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 1)));
      // Plan 70-05: child's kind is explicitly 'file' so the new recursive
      // verifySubtreeClean does not attempt to descend past this leaf — the static
      // unsealNode mock below returns the SAME rootNode for every call, which would
      // otherwise infinite-loop if recursion were attempted into a 'folder' child.
      return new TextEncoder().encode(JSON.stringify(makePublishedNode(CHILD_ID, 1, 'file')));
    });
    mockFns.unsealNode.mockResolvedValue(rootNode);

    // RED: verifySubtreeClean throws "not implemented — phase 64" → test fails
    // GREEN: returns { isDirty: false, frontier: [] }
    const result = await verifySubtreeClean(NODE_IPNS, T07_ROOT_READ_KEY, createMockContext());
    expect(result.isDirty).toBe(false);
    expect(result.frontier).toHaveLength(0);
  });

  it('Test 2: returns { isDirty: true, frontier: [child] } when child generation mismatches', async () => {
    // Root: children[{generation: 0}] (parent mirror = 0), child published at generation 1 → dirty
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 1,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 0, // parent mirror is stale (0), child was already rotated to 1
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
    });

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 2n,
      signatureVerified: true,
    }));
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 1)));
      // Child is at generation 1 (rotated by prior run; parent mirror still shows 0)
      return new TextEncoder().encode(JSON.stringify(makePublishedNode(CHILD_ID, 1)));
    });
    mockFns.unsealNode.mockResolvedValue(rootNode);

    // RED: verifySubtreeClean throws → test fails
    // GREEN: returns { isDirty: true, frontier: [{ ipnsName: CHILD_IPNS, nodeId: CHILD_ID }] }
    const result = await verifySubtreeClean(NODE_IPNS, T07_ROOT_READ_KEY, createMockContext());
    expect(result.isDirty).toBe(true);
    expect(result.frontier).toHaveLength(1);
    expect(result.frontier[0].ipnsName).toBe(CHILD_IPNS);
    expect(result.frontier[0].nodeId).toBe(CHILD_ID);
  });
});

// ---------------------------------------------------------------------------
// Plan 70-05 Task 1 RED — verifySubtreeClean full-subtree recursion (SC#2)
// ---------------------------------------------------------------------------

// Shared IPNS/id constants for the depth-2 fixture (root -> subfolder -> grandchild).
const P05_SUBFOLDER_ID = 'subfolder-2222-3333-4444-555555555555';
const P05_SUBFOLDER_IPNS = 'k51subfolder0000000000000000000000000000000000000000000000000000';
const P05_GRANDCHILD_ID = 'grandchild-3333-4444-5555-666666666666';
const P05_GRANDCHILD_IPNS = 'k51grandchildp05000000000000000000000000000000000000000000000000';
const P05_SUBFOLDER_READ_KEY = new Uint8Array(32).fill(0x21);
const P05_GRANDCHILD_READ_KEY = new Uint8Array(32).fill(0x22);

describe('verifySubtreeClean — full-subtree recursion (Plan 70-05 SC#2)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('Test 1 (Plan 70-05): dirty at depth 2 — grandchild dirty edge carries a usable engine-derived nodeReadKey', async () => {
    // root -[clean edge]-> subfolder -[dirty edge]-> grandchild
    const rootFolderNode = makeFolderNode({
      id: NODE_ID,
      generation: 5,
      children: [
        {
          name: 'subfolder',
          ipnsName: P05_SUBFOLDER_IPNS,
          generation: 3, // matches subfolder's published generation (clean edge) — recurse into it
          versionFloor: 0n,
          readKeySealed: 'subfoldersealed==',
        },
      ],
    });
    const subfolderNode = makeFolderNode({
      id: P05_SUBFOLDER_ID,
      generation: 3,
      children: [
        {
          name: 'grandchild',
          ipnsName: P05_GRANDCHILD_IPNS,
          generation: 1, // parent (subfolder) mirror is stale — grandchild already rotated to 2
          versionFloor: 0n,
          readKeySealed: 'grandchildsealed==',
        },
      ],
    });

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => {
      const cidByIpns: Record<string, string> = {
        [NODE_IPNS]: 'bafy-root',
        [P05_SUBFOLDER_IPNS]: 'bafy-subfolder',
        [P05_GRANDCHILD_IPNS]: 'bafy-grandchild',
      };
      const cid = cidByIpns[ipnsName];
      if (!cid) return null;
      return { cid, sequenceNumber: 1n, signatureVerified: true };
    });
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 5, 'folder')));
      if (cid === 'bafy-subfolder')
        return new TextEncoder().encode(
          JSON.stringify(makePublishedNode(P05_SUBFOLDER_ID, 3, 'folder'))
        );
      // Grandchild's own publish already advanced to generation 2 — dirty relative to
      // subfolder's stale mirror (generation 1).
      return new TextEncoder().encode(
        JSON.stringify(makePublishedNode(P05_GRANDCHILD_ID, 2, 'file'))
      );
    });
    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) => {
        if (published.id === NODE_ID) return rootFolderNode;
        if (published.id === P05_SUBFOLDER_ID) return subfolderNode;
        throw new Error(`unexpected unsealNode call for ${published.id}`);
      }
    );
    mockFns.unsealChildReadKey.mockImplementation(async (sealed: string) => {
      if (sealed === 'subfoldersealed==') return P05_SUBFOLDER_READ_KEY;
      if (sealed === 'grandchildsealed==') return P05_GRANDCHILD_READ_KEY;
      throw new Error(`unexpected sealed value: ${sealed}`);
    });

    // RED (depth-1-only implementation): root's only immediate child (subfolder) is a
    // CLEAN edge (generation 3 === 3), so the old implementation never looks past it —
    // returns { isDirty: false, frontier: [] }, missing the depth-2 dirty grandchild.
    // GREEN: recurses into the clean subfolder edge and finds the dirty grandchild edge.
    const result = await verifySubtreeClean(NODE_IPNS, T07_ROOT_READ_KEY, createMockContext());

    expect(result.isDirty).toBe(true);
    expect(result.frontier).toHaveLength(1);
    expect(result.frontier[0]).toMatchObject({
      ipnsName: P05_GRANDCHILD_IPNS,
      nodeId: P05_GRANDCHILD_ID,
      parentIpnsName: P05_SUBFOLDER_IPNS,
      childPubKind: 'file',
      enqueuedGeneration: 1,
    });
    expect(result.frontier[0].nodeReadKey).toEqual(P05_GRANDCHILD_READ_KEY);
  });

  it('Test 2 (Plan 70-05): missing root IPNS record surfaces as dirty, never silently clean', async () => {
    mockFns.resolveIpnsRecord.mockResolvedValue(null);

    // RED: old implementation explicitly returns { isDirty: false, frontier: [] } on a
    // missing root — this assertion fails against that behavior.
    // GREEN: missing root ⇒ isDirty: true.
    const result = await verifySubtreeClean(NODE_IPNS, T07_ROOT_READ_KEY, createMockContext());

    expect(result.isDirty).toBe(true);
    expect(mockFns.fetchFromIpfs).not.toHaveBeenCalled();
  });

  it('Test 3 (Plan 70-05): clean multi-level tree — no dirty edges at any depth returns isDirty false', async () => {
    // root -[clean]-> subfolder -[clean]-> grandchild (file, leaf)
    const rootFolderNode = makeFolderNode({
      id: NODE_ID,
      generation: 5,
      children: [
        {
          name: 'subfolder',
          ipnsName: P05_SUBFOLDER_IPNS,
          generation: 3,
          versionFloor: 0n,
          readKeySealed: 'subfoldersealed==',
        },
      ],
    });
    const subfolderNode = makeFolderNode({
      id: P05_SUBFOLDER_ID,
      generation: 3,
      children: [
        {
          name: 'grandchild',
          ipnsName: P05_GRANDCHILD_IPNS,
          generation: 2, // matches grandchild's own published generation — clean
          versionFloor: 0n,
          readKeySealed: 'grandchildsealed==',
        },
      ],
    });

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => {
      const cidByIpns: Record<string, string> = {
        [NODE_IPNS]: 'bafy-root',
        [P05_SUBFOLDER_IPNS]: 'bafy-subfolder',
        [P05_GRANDCHILD_IPNS]: 'bafy-grandchild',
      };
      const cid = cidByIpns[ipnsName];
      if (!cid) return null;
      return { cid, sequenceNumber: 1n, signatureVerified: true };
    });
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 5, 'folder')));
      if (cid === 'bafy-subfolder')
        return new TextEncoder().encode(
          JSON.stringify(makePublishedNode(P05_SUBFOLDER_ID, 3, 'folder'))
        );
      return new TextEncoder().encode(
        JSON.stringify(makePublishedNode(P05_GRANDCHILD_ID, 2, 'file'))
      );
    });
    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) => {
        if (published.id === NODE_ID) return rootFolderNode;
        if (published.id === P05_SUBFOLDER_ID) return subfolderNode;
        throw new Error(`unexpected unsealNode call for ${published.id}`);
      }
    );
    mockFns.unsealChildReadKey.mockImplementation(async (sealed: string) => {
      if (sealed === 'subfoldersealed==') return P05_SUBFOLDER_READ_KEY;
      if (sealed === 'grandchildsealed==') return P05_GRANDCHILD_READ_KEY;
      throw new Error(`unexpected sealed value: ${sealed}`);
    });

    const result = await verifySubtreeClean(NODE_IPNS, T07_ROOT_READ_KEY, createMockContext());

    expect(result.isDirty).toBe(false);
    expect(result.frontier).toHaveLength(0);
  });
});

describe('rotateReadFromNode — resume guard (Plan 64-07)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('Test 3: resume with dirty child triggers D-09 parent re-publish (does not short-circuit complete)', async () => {
    // Root already in completedNodeIds: rotateOne returns skipped.
    // Child has dirty edge: parent mirror = 0, child published gen = 1.
    // Expected (GREEN): verifySubtreeClean detects dirty → frontier seeded → the child is
    //   safely double-rotated (Plan 70-06 / design §4.5 — no convergence-skip guard) →
    //   D-09 publishWithCas called for root re-publish once the child completes.
    // RED: resume guard marks complete immediately → publishWithCas NOT called → FAILS.
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 1,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 0, // parent mirror stale
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
    });
    // Plan 70-06: the child is now genuinely re-entered via rotateOne (safe
    // double-rotation), so unsealNode must return a CHILD-shaped node (distinct
    // id, no children) for the child's own published envelope — a single static
    // rootNode return value here would collide nodeId derivation with the ROOT's
    // id and corrupt the child's own idempotency check.
    const childNode = makeFolderNode({ id: CHILD_ID, generation: 1, children: [] });

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 3n,
      signatureVerified: true,
    }));
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 1)));
      // Child is already at generation 1
      return new TextEncoder().encode(JSON.stringify(makePublishedNode(CHILD_ID, 1)));
    });
    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) =>
        published.id === NODE_ID ? rootNode : childNode
    );
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation)
    );
    mockFns.sealChildReadKey.mockResolvedValue('resealed==');
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-updated',
      newSequenceNumber: 4n,
      publishedData: [],
      prunedCids: [],
    });

    const jobRecord = makeJobRecord({
      rootNodeId: NODE_ID,
      completedNodeIds: new Set([NODE_ID]), // resume: root already committed
    });

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: T07_ROOT_READ_KEY,
      rootIpnsPrivateKey: T07_ROOT_IPNS_KEY,
      nodeKeySource: () => ({ privateKey: T07_CHILD_IPNS_KEY, publicKey: T07_STUB_PUB_KEY }),
      jobRecord,
      ctx: createMockContext(),
    });

    // In RED: publishWithCas NOT called (resume guard marks complete immediately).
    // In GREEN: publishWithCas IS called for D-09 parent re-publish after dirty frontier BFS.
    expect(mockFns.publishWithCas).toHaveBeenCalled();
    expect(jobRecord.status).toBe('complete');
  });

  it('Test 4: clean resume (isDirty: false) sets status complete and calls persistCallback', async () => {
    // Root in completedNodeIds, clean subtree (all child mirrors match).
    // Expected: status='complete' and persistCallback called.
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 1,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 1, // parent mirror matches child's published gen → clean
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
    });

    const persistCallback = vi.fn();

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 2n,
      signatureVerified: true,
    }));
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 1)));
      // Plan 70-05: child's kind is explicitly 'file' so the new recursive
      // verifySubtreeClean does not attempt to descend past this leaf — the static
      // unsealNode mock below returns the SAME rootNode for every call, which would
      // otherwise infinite-loop if recursion were attempted into a 'folder' child.
      return new TextEncoder().encode(JSON.stringify(makePublishedNode(CHILD_ID, 1, 'file')));
    });
    mockFns.unsealNode.mockResolvedValue(rootNode);
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 3n,
      publishedData: [],
      prunedCids: [],
    });

    const jobRecord = makeJobRecord({
      rootNodeId: NODE_ID,
      completedNodeIds: new Set([NODE_ID]),
      persistCallback,
    });

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: T07_ROOT_READ_KEY,
      rootIpnsPrivateKey: T07_ROOT_IPNS_KEY,
      jobRecord,
      ctx: createMockContext(),
    });

    expect(jobRecord.status).toBe('complete');
    expect(persistCallback).toHaveBeenCalled();
  });
});

const MISSING_CHILD_IPNS_70_06 =
  'k51missingfrontier00000000000000000000000000000000000000000000000';

describe('rotateReadFromNode — fresh-record resume via safe double-rotation (Plan 70-06 SC#3, supersedes 64-07 no-double-bump guard)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('Test 1 (Plan 70-06): fresh job, child already at baseline+1 — safe double-rotation recovers it (sealNode/publishWithCas ARE invoked for child, no guard blocks it)', async () => {
    // Fresh job: empty completedNodeIds, root at generation 0.
    // Root's SealedChildRef shows child at generation 0 (baseline).
    // BUT child is ALREADY published at generation 1 (rotated by a prior crashed run).
    //
    // Plan 70-06 / design §4.5: crash recovery converges via SAFE DOUBLE-ROTATION,
    // not a no-double-bump skip. The pre-rotation verifySubtreeClean probe finds
    // this dirty edge and — since no convergence guard blocks it anymore — the
    // child DOES get rotated again via the normal rotateOne call.
    //
    // RED (old 64-07 behavior): a no-double-bump convergence guard skips rotateOne
    // for the child → sealNode/publishWithCas NEVER called with CHILD_ID/CHILD_IPNS
    // → these "toContain" assertions FAIL.
    // GREEN (Plan 70-06): no guard blocks it → sealNode/publishWithCas ARE called
    // for the child → assertions PASS.
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 0,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 0, // baseline: parent mirror shows 0 (child not yet rotated from parent's view)
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
    });

    const publishedRootGen0 = makePublishedNode(NODE_ID, 0);
    const publishedChildGen1 = makePublishedNode(CHILD_ID, 1); // ALREADY rotated by prior run

    const sealNodeCalls: string[] = [];
    const publishWithCasCalls: string[] = [];

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 1n,
      signatureVerified: true,
    }));
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root') return new TextEncoder().encode(JSON.stringify(publishedRootGen0));
      return new TextEncoder().encode(JSON.stringify(publishedChildGen1));
    });
    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) => {
        if (published.id === NODE_ID) return rootNode;
        return makeFolderNode({ id: CHILD_ID, generation: 1, children: [] });
      }
    );
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) => {
      sealNodeCalls.push(node.id);
      return makePublishedNode(node.id, node.generation + 1);
    });
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
    mockFns.publishWithCas.mockImplementation(async (params: { ipnsName: string }) => {
      publishWithCasCalls.push(params.ipnsName);
      return { cid: 'bafy-new', newSequenceNumber: 2n, publishedData: [], prunedCids: [] };
    });

    const jobRecord = makeJobRecord({
      rootNodeId: NODE_ID,
      completedNodeIds: new Set<string>(), // FRESH job
      status: 'pending',
    });

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0x77),
      rootIpnsPrivateKey: T07_ROOT_IPNS_KEY,
      nodeKeySource: () => ({ privateKey: T07_CHILD_IPNS_KEY, publicKey: T07_STUB_PUB_KEY }),
      jobRecord,
      ctx: createMockContext(),
    });

    // Root MUST rotate (sealNode called with NODE_ID)
    expect(sealNodeCalls).toContain(NODE_ID);
    // Child MUST ALSO be rotated again (safe double-rotation — design §4.5) —
    // no convergence guard skips it.
    expect(sealNodeCalls).toContain(CHILD_ID);
    // publishWithCas MUST be called for CHILD_IPNS (child rotation NOT skipped)
    expect(publishWithCasCalls).toContain(CHILD_IPNS);
  });

  it('Test 2 (Plan 70-06): stale rootReadKey throws RootKeyStaleError, not a generic AEAD/unseal error', async () => {
    // Root record EXISTS and resolves, but the caller-supplied rootReadKey cannot
    // unseal it (the root was rotated by a lost prior run and this client never
    // saw the new key — the genuinely-unrecoverable window, RESEARCH Pitfall 4).
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-root',
      sequenceNumber: 3n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 3)))
    );
    mockFns.unsealNode.mockRejectedValue(new Error('AEAD authentication failed'));

    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID, completedNodeIds: new Set<string>() });

    // RED (pre-70-06): the probe doesn't exist — rotateOne's own unseal throws the
    // generic 'AEAD authentication failed' Error verbatim (not RootKeyStaleError,
    // and not the probe's distinct message) → the name/message assertions below
    // FAIL. (Not asserted via `.rejects.toThrow(RootKeyStaleError)` alone — with
    // the pre-70-06 engine.ts not yet exporting RootKeyStaleError at all, that
    // binding would import as `undefined`, and vitest's toThrow(undefined)
    // degrades to a vacuous "throws something" check that passes against ANY
    // thrown error — asserting `.name`/`.message` explicitly avoids that false
    // green.)
    // GREEN: the entry-gate probe throws a real RootKeyStaleError, with its own
    // distinct message, BEFORE rotateOne(root) ever runs → assertions PASS.
    let caughtError: unknown;
    try {
      await rotateReadFromNode({
        rootNodeId: NODE_ID,
        rootNodeIpnsName: NODE_IPNS,
        rootReadKey: T07_ROOT_READ_KEY,
        rootIpnsPrivateKey: T07_ROOT_IPNS_KEY,
        jobRecord,
        ctx: createMockContext(),
      });
    } catch (err) {
      caughtError = err;
    }
    expect(caughtError).toBeInstanceOf(Error);
    expect(caughtError).toBeInstanceOf(RootKeyStaleError);
    expect((caughtError as Error).name).toBe('RootKeyStaleError');
    expect((caughtError as Error).message).toMatch(/cannot unseal the currently-published root/i);
    expect((caughtError as Error).message).not.toBe('AEAD authentication failed');

    // The stale-key probe must fail BEFORE any actual rotation attempt.
    expect(mockFns.publishWithCas).not.toHaveBeenCalled();
  });

  it('Test 3 (Plan 70-06 SC#4): grantCallbacks/innerGrants on RotationParams reach queryGrantsFn via the public rotateReadFromNode walk', async () => {
    // Root-only (no children), fresh job. Driving the PUBLIC rotateReadFromNode
    // entrypoint (not a direct rotateOne injection) with grantCallbacks +
    // innerGrants supplied on RotationParams.
    const rootNode = makeFolderNode({ id: NODE_ID, generation: 0, children: [] });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-root',
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

    const queryGrantsFn = vi.fn().mockResolvedValue([]);
    const grantCallbacks: GrantRemintCallbacks = {
      queryGrantsFn,
      updateGrantFn: vi.fn(),
      deleteGrantFn: vi.fn(),
    };

    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID, completedNodeIds: new Set<string>() });

    // RED: RotationParams has no grantCallbacks/innerGrants fields (or they exist
    // but are never threaded to rotateOne) → queryGrantsFn is never invoked →
    // this assertion FAILS.
    // GREEN: threaded through to rotateOne(root) → reMintGrantsRootedAt runs
    // (innerGrants non-empty) → queryGrantsFn IS invoked → assertion PASSES.
    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: T07_ROOT_READ_KEY,
      rootIpnsPrivateKey: T07_ROOT_IPNS_KEY,
      innerGrants: [{}],
      grantCallbacks,
      jobRecord,
      ctx: createMockContext(),
    });

    expect(queryGrantsFn).toHaveBeenCalledWith(NODE_ID);
  });

  it('Test 4 (Plan 70-06 / T-70-12): a missing child IPNS record is fail-closed accounted — the parent still converges via its batched republish', async () => {
    // Root has TWO children: CHILD_IPNS (resolves fine, rotates normally) and
    // MISSING_CHILD_IPNS_70_06 (its IPNS record no longer resolves — a data
    // inconsistency). A silent `continue` that never decrements pendingChildCount
    // for the missing child leaves the parent's batched D-09 republish stuck
    // forever (pendingChildCount never reaches 0).
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 0,
      children: [
        {
          name: 'child-a',
          ipnsName: CHILD_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'childAsealed==',
        },
        {
          name: 'child-missing',
          ipnsName: MISSING_CHILD_IPNS_70_06,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'missingsealed==',
        },
      ],
    });
    const publishedRootGen0 = makePublishedNode(NODE_ID, 0);
    const publishedChildAGen0 = makePublishedNode(CHILD_ID, 0);

    const publishWithCasCalls: string[] = [];

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => {
      if (ipnsName === NODE_IPNS) {
        return { cid: 'bafy-root', sequenceNumber: 1n, signatureVerified: true };
      }
      if (ipnsName === CHILD_IPNS) {
        return { cid: 'bafy-child-a', sequenceNumber: 1n, signatureVerified: true };
      }
      // MISSING_CHILD_IPNS_70_06: the record was never published / is gone.
      return null;
    });
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root') return new TextEncoder().encode(JSON.stringify(publishedRootGen0));
      return new TextEncoder().encode(JSON.stringify(publishedChildAGen0));
    });
    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) => {
        if (published.id === NODE_ID) return rootNode;
        return makeFolderNode({ id: CHILD_ID, generation: 0, children: [] });
      }
    );
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation + 1)
    );
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
    mockFns.publishWithCas.mockImplementation(async (params: { ipnsName: string }) => {
      publishWithCasCalls.push(params.ipnsName);
      return { cid: 'bafy-new', newSequenceNumber: 2n, publishedData: [], prunedCids: [] };
    });

    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID, completedNodeIds: new Set<string>() });

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: T07_ROOT_READ_KEY,
      rootIpnsPrivateKey: T07_ROOT_IPNS_KEY,
      nodeKeySource: () => ({ privateKey: T07_CHILD_IPNS_KEY, publicKey: T07_STUB_PUB_KEY }),
      jobRecord,
      ctx: createMockContext(),
    });

    expect(jobRecord.status).toBe('complete');
    // RED (silent continue, no accounting): pendingChildCount never reaches 0 —
    // root's batched republish never fires — NODE_IPNS appears only ONCE
    // (root's own initial rotation publish) → this assertion FAILS (expects 2).
    // GREEN (fail-closed accounting): the missing child is explicitly accounted
    // for — pendingChildCount DOES reach 0 once child-a completes — root's
    // batched republish fires — NODE_IPNS appears TWICE → assertion PASSES.
    const rootPublishCount = publishWithCasCalls.filter((n) => n === NODE_IPNS).length;
    expect(rootPublishCount).toBe(2);
  });

  it('Test 5 (Plan 70-06 SC#6 / T-70-10): dirty-resume-republish returns a FRESH COPY readKey, never an alias of the caller-owned rootReadKey', async () => {
    // Same fixture shape as the classic 64-07 dirty-resume test: root already in
    // completedNodeIds (same-session resume), one dirty child below it.
    const rootNode = makeFolderNode({
      id: NODE_ID,
      generation: 1,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 0, // parent mirror stale
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
    });

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 3n,
      signatureVerified: true,
    }));
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 1)));
      return new TextEncoder().encode(JSON.stringify(makePublishedNode(CHILD_ID, 1)));
    });
    mockFns.unsealNode.mockResolvedValue(rootNode);
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNode(node.id, node.generation)
    );
    mockFns.sealChildReadKey.mockResolvedValue('resealed==');
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-updated',
      newSequenceNumber: 4n,
      publishedData: [],
      prunedCids: [],
    });

    const jobRecord = makeJobRecord({
      rootNodeId: NODE_ID,
      completedNodeIds: new Set([NODE_ID]), // resume: root already committed
    });

    const rootReadKeyParam = new Uint8Array(32).fill(0x99);

    // RED: the dirty-resume path always returns `undefined` (rootResult.skipped
    // unconditionally short-circuits the return) → `result` is undefined →
    // `.toBeDefined()` FAILS.
    // GREEN: a dirty-resume republish occurred → a truthy RotateReadResult is
    // returned whose readKey is a FRESH COPY (new Uint8Array), never the SAME
    // object reference as the caller-supplied rootReadKeyParam.
    const result = await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: rootReadKeyParam,
      rootIpnsPrivateKey: T07_ROOT_IPNS_KEY,
      nodeKeySource: () => ({ privateKey: T07_CHILD_IPNS_KEY, publicKey: T07_STUB_PUB_KEY }),
      jobRecord,
      ctx: createMockContext(),
    });

    expect(result).toBeDefined();
    // Buffer-IDENTITY assertion: never the same object as the caller's buffer.
    expect(result?.readKey).not.toBe(rootReadKeyParam);
    // But byte-equal (a faithful copy of the root's current valid key).
    expect(result?.readKey).toEqual(rootReadKeyParam);
  });
});

// ---------------------------------------------------------------------------
// Plan 64-07 Task 2 RED — D-07 job-record ordering, terminal persist, zeroization
// ---------------------------------------------------------------------------

describe('rotateOne — D-07 completedNodeIds ordering (Plan 64-07)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-node-cid',
      sequenceNumber: 3n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 2)))
    );
    mockFns.unsealNode.mockResolvedValue(
      makeFolderNode({ id: NODE_ID, generation: 2, children: [] })
    );
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 3));
    mockFns.sealChildReadKey.mockResolvedValue('newchildsealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new-cid',
      newSequenceNumber: 4n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('Test 1: reMintGrantsRootedAt throws → nodeId NOT added to completedNodeIds (D-07)', async () => {
    // D-07 ordering bug: completedNodeIds.add(nodeId) runs BEFORE reMintGrantsRootedAt.
    // If reMintGrantsRootedAt throws, nodeId is already in completedNodeIds → silent skip on resume.
    //
    // RED: add before reMint → nodeId IS in completedNodeIds after throw → assertion fails.
    // GREEN: add after reMint → nodeId NOT in completedNodeIds after throw → assertion passes.
    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID });
    const ctx = createMockContext();

    const failingCallbacks: GrantRemintCallbacks = {
      queryGrantsFn: vi.fn().mockRejectedValue(new Error('queryGrants failed')),
      updateGrantFn: vi.fn(),
      deleteGrantFn: vi.fn(),
    };

    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: new Uint8Array(32).fill(0x11),
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 3n,
        jobRecord,
        ctx,
        innerGrants: [{}],
        grantCallbacks: failingCallbacks,
      })
    ).rejects.toThrow('queryGrants failed');

    // D-07: after reMint failure, nodeId must NOT be in completedNodeIds.
    // In RED: completedNodeIds.add ran before the throw → this assertion FAILS.
    // In GREEN: completedNodeIds.add runs after reMint → this assertion PASSES.
    expect(jobRecord.completedNodeIds.has(NODE_ID)).toBe(false);
  });
});

describe('rotateReadFromNode — terminal persist and child-key zeroization (Plan 64-07)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('Test 2: terminal jobRecord.status = "complete" is persisted via persistCallback', async () => {
    // Root-only job (no children) — BFS loop is empty.
    // Expected: persistCallback called TWICE — once after root commit (status in-progress),
    // once at terminal status='complete'.
    //
    // RED: persistCallback called only once (after root commit) → toHaveBeenCalledTimes(2) FAILS.
    // GREEN: persistCallback called at terminal too → assertion PASSES.
    const rootNode = makeFolderNode({ id: NODE_ID, generation: 0, children: [] });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-root',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0)))
    );
    mockFns.unsealNode.mockResolvedValue(rootNode);
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 1));
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });

    const persistCallback = vi.fn();
    const jobRecord = makeJobRecord({ rootNodeId: NODE_ID, persistCallback });

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: new Uint8Array(32).fill(0xcc),
      rootIpnsPrivateKey: new Uint8Array(32).fill(0x10),
      jobRecord,
      ctx: createMockContext(),
    });

    expect(jobRecord.status).toBe('complete');
    // In RED: only 1 call (after root commit). In GREEN: 2 calls (root + terminal).
    expect(persistCallback).toHaveBeenCalledTimes(2);
  });

  it('Test 3: queue-derived child readKey zeroed after grandchildren enqueued; rootReadKey not zeroed', async () => {
    // Root with one child, child has no grandchildren.
    // item.nodeReadKey (child's readKey, queue-derived) must be zeroed by the engine
    // after the child's grandchildren are enqueued (D-09 terminal-owner rule for BFS keys).
    // rootReadKey (caller-supplied) must NOT be zeroed (caller is terminal owner — D-09).
    //
    // RED: no zeroization → capturedChildReadKeys[0] is all-0x42 → assertion fails.
    // GREEN: zeroed after grandchildren loop → capturedChildReadKeys[0] is all-0x00 → passes.
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
    const childNode = makeFolderNode({ id: CHILD_ID, generation: 0, children: [] });

    const capturedChildReadKeys: Uint8Array[] = [];

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 1n,
      signatureVerified: true,
    }));
    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-root')
        return new TextEncoder().encode(JSON.stringify(makePublishedNode(NODE_ID, 0)));
      return new TextEncoder().encode(JSON.stringify(makePublishedNode(CHILD_ID, 0)));
    });
    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) => {
        if (published.id === NODE_ID) return rootNode;
        return childNode;
      }
    );
    mockFns.sealNode.mockResolvedValue(makePublishedNode(NODE_ID, 1));
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.unsealChildReadKey.mockImplementation(async () => {
      const key = new Uint8Array(32).fill(0x42);
      capturedChildReadKeys.push(key);
      return key;
    });
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });

    const rootReadKey = new Uint8Array(32).fill(0xcc);

    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey,
      rootIpnsPrivateKey: new Uint8Array(32).fill(0x10),
      nodeKeySource: () => ({
        privateKey: new Uint8Array(32).fill(0x12),
        publicKey: new Uint8Array(32).fill(0x01),
      }),
      jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
      ctx: createMockContext(),
    });

    // rootReadKey must NOT be zeroed (caller is terminal owner — D-09).
    // This passes in both RED and GREEN: regression gate.
    expect(rootReadKey.some((b) => b !== 0)).toBe(true);

    // Queue-derived child readKey (item.nodeReadKey) MUST be zeroed after grandchildren enqueued.
    // In RED: not zeroed → some bytes are 0x42 → assertion fails.
    // In GREEN: zeroed → all bytes are 0 → assertion passes.
    expect(capturedChildReadKeys.length).toBeGreaterThan(0);
    expect(capturedChildReadKeys[0].every((b) => b === 0)).toBe(true);
  });
});
