/**
 * TDD RED phase — write-plane preservation during read-rotation (Plan 65-05 Task 1).
 *
 * These tests assert that `rotateOne` / `rotateReadFromNode`:
 *   1. Calls `unsealNode(published, parentReadKey, nodeWriteKey)` so the write-body
 *      is recovered when the caller supplies a real writeKey.
 *   2. Calls `sealNode(updatedNode, readKeyPrime, nodeWriteKey)` with the SAME
 *      nodeWriteKey — never an all-zeros placeholder.
 *   3. The sealed node handed to sealNode carries the pre-rotation writeBody unchanged
 *      (ipnsPrivateKey / writeChildren preserved — read/write planes are independent).
 *   4. Fail-closed: when the published envelope has `writeSealed` but no valid writeKey
 *      is threaded, rotateOne throws rather than silently dropping / corrupting the
 *      write plane (RESEARCH Pitfall 2 / T-65-17).
 *
 * RED failure reasons (against the current unmodified engine):
 *   - Tests 1, 2, 3: rotateOne calls `unsealNode(pub, parentReadKey)` (2-arg) so the
 *     write-body is absent; `sealNode` is invoked with `PLACEHOLDER_WRITE_KEY` (all-zeros).
 *   - Tests 4, 5: no writeSealed-without-writeKey guard exists in the engine.
 *
 * GREEN (Task 2): all tests pass after:
 *   - `nodeWriteKey?: Uint8Array` added to `RotateOneParams`;
 *   - `nodeKeySource` return extended with optional `writeKey?: Uint8Array`;
 *   - `rotateOne` unseal + reseal wired to use the real writeKey;
 *   - Fail-closed guard added;
 *   - `PLACEHOLDER_WRITE_KEY` removed.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { rotateOne, rotateReadFromNode, type RotationJobRecord } from '../../rotation/engine';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks — same hoisted vi.fn() pattern as engine.test.ts
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  resolveIpnsRecord: vi.fn(),
  fetchFromIpfs: vi.fn(),
  publishWithCas: vi.fn(),
  unsealNode: vi.fn(),
  sealNode: vi.fn(),
  sealChildReadKey: vi.fn(),
  unsealChildReadKey: vi.fn(),
  sealChildWriteKey: vi.fn(),
  unsealChildWriteKey: vi.fn(),
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
  sealChildWriteKey: mockFns.sealChildWriteKey,
  unsealChildWriteKey: mockFns.unsealChildWriteKey,
  CryptoError: class CryptoError extends Error {
    code: string;
    constructor(msg: string, code: string) {
      super(msg);
      this.code = code;
    }
  },
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NODE_ID = 'write-node-aaaa-1111-bbbb-cccccccccccc';
const NODE_IPNS = 'k51writechild000000000000000000000000000000000000000000000000000';
const PARENT_IPNS = 'k51writeparent00000000000000000000000000000000000000000000000000';

/** Real non-zero IPNS signing key for the node. */
const NODE_IPNS_PRIVATE_KEY = new Uint8Array(32).fill(0x11);
/** Parent read key (caller-owned — must never be zeroed by rotateOne). */
const PARENT_READ_KEY = new Uint8Array(32).fill(0xab);
/** Real non-zero writeKey for the node (NOT all-zeros). */
const NODE_WRITE_KEY = new Uint8Array(32).fill(0xcc);

/**
 * Simulated Ed25519 private key seed stored inside the write-body.
 * After read-rotation this value must be byte-identical (write plane preserved).
 */
const IPNS_PRIVATE_KEY_IN_WRITE_BODY = new Uint8Array(32).fill(0xdd);

function makeJobRecord(overrides?: Partial<RotationJobRecord>): RotationJobRecord {
  return {
    rootNodeId: NODE_ID,
    status: 'pending',
    completedNodeIds: new Set<string>(),
    frontier: [],
    ...overrides,
  };
}

/** A PublishedNode whose envelope HAS a writeSealed field — write-capable node. */
function makePublishedNodeWithWriteSealed(
  nodeId: string,
  generation: number
): import('@cipherbox/core').PublishedNode {
  return {
    schema: 'node/v3',
    kind: 'folder',
    id: nodeId,
    generation,
    aeadVersion: 1,
    readSealed: 'readSealed==',
    writeSealed: 'writeSealed==',
  };
}

/** In-memory node with a real writeBody (the result of unsealing with writeKey). */
function makeNodeWithWriteBody(
  overrides?: Partial<import('@cipherbox/core').Node>
): import('@cipherbox/core').Node {
  return {
    schema: 'node/v3',
    kind: 'folder',
    id: NODE_ID,
    generation: 1,
    createdAt: 1000,
    modifiedAt: 2000,
    children: [],
    writeBody: {
      ipnsPrivateKey: new Uint8Array(IPNS_PRIVATE_KEY_IN_WRITE_BODY),
      writeChildren: [],
    },
    ...overrides,
  } as import('@cipherbox/core').Node;
}

/** In-memory node WITHOUT writeBody (write-plane dropped — bad current behavior). */
function makeNodeWithoutWriteBody(generation = 1): import('@cipherbox/core').Node {
  return {
    schema: 'node/v3',
    kind: 'folder',
    id: NODE_ID,
    generation,
    createdAt: 1000,
    modifiedAt: 2000,
    children: [],
  } as import('@cipherbox/core').Node;
}

// ---------------------------------------------------------------------------
// Suite 1: Write-plane preservation (rotateOne single-node path)
// ---------------------------------------------------------------------------

describe('rotateOne — write-body node: unsealNode receives nodeWriteKey (Plan 65-05)', () => {
  beforeEach(() => {
    vi.resetAllMocks();

    const published = makePublishedNodeWithWriteSealed(NODE_ID, 1);
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-write-cid',
      sequenceNumber: 5n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(new TextEncoder().encode(JSON.stringify(published)));
    // Default: return a node WITH writeBody when called with any args
    mockFns.unsealNode.mockResolvedValue(makeNodeWithWriteBody());
    mockFns.sealNode.mockResolvedValue(makePublishedNodeWithWriteSealed(NODE_ID, 2));
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new-cid',
      newSequenceNumber: 6n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('Test 1: unsealNode is called with the nodeWriteKey as 3rd argument', async () => {
    // RED: rotateOne calls `unsealNode(published, parentReadKey)` — 2 args, no writeKey.
    //      Assertion on the 3rd arg being NODE_WRITE_KEY will fail.
    // GREEN: rotateOne calls `unsealNode(published, parentReadKey, nodeWriteKey)` — passes.

    const capturedUnsealArgs: unknown[][] = [];
    mockFns.unsealNode.mockImplementation(async (...args: unknown[]) => {
      capturedUnsealArgs.push(args);
      // Return node with writeBody regardless (so test can complete and check sealNode too)
      return makeNodeWithWriteBody();
    });

    // Pass nodeWriteKey as an extra property — vitest uses esbuild (no type-check at run time)
    // The param is future-proof: RotateOneParams gains `nodeWriteKey` in Task 2 GREEN.
    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      nodeIpnsPrivateKey: NODE_IPNS_PRIVATE_KEY,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ...({ nodeWriteKey: NODE_WRITE_KEY } as any),
    }).catch(() => {
      // May throw in RED — that is acceptable; we inspect captured args below.
    });

    // At least one unsealNode call occurred
    expect(capturedUnsealArgs.length).toBeGreaterThan(0);

    const thirdArg = capturedUnsealArgs[0]?.[2] as Uint8Array | undefined;
    // RED: thirdArg is undefined (no writeKey passed to unsealNode) → assertion fails.
    // GREEN: thirdArg equals NODE_WRITE_KEY → passes.
    expect(thirdArg).toBeInstanceOf(Uint8Array);
    expect(thirdArg).toEqual(NODE_WRITE_KEY);
  });

  it('Test 2: sealNode receives the real nodeWriteKey — not an all-zeros placeholder', async () => {
    // RED: sealNode 3rd arg is PLACEHOLDER_WRITE_KEY = new Uint8Array(32) (all-zeros).
    //      Assertion that writeKey is NOT all-zeros fails.
    // GREEN: sealNode 3rd arg is NODE_WRITE_KEY (0xcc fill) → passes.

    const capturedSealWriteKeys: Uint8Array[] = [];
    mockFns.sealNode.mockImplementation(
      async (_node: import('@cipherbox/core').Node, _readKey: Uint8Array, writeKey: Uint8Array) => {
        capturedSealWriteKeys.push(new Uint8Array(writeKey));
        return makePublishedNodeWithWriteSealed(NODE_ID, 2);
      }
    );

    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      nodeIpnsPrivateKey: NODE_IPNS_PRIVATE_KEY,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ...({ nodeWriteKey: NODE_WRITE_KEY } as any),
    }).catch(() => {});

    expect(capturedSealWriteKeys.length).toBeGreaterThan(0);
    const sealWriteKey = capturedSealWriteKeys[0];
    expect(sealWriteKey).toBeInstanceOf(Uint8Array);
    // RED: sealWriteKey is all-zeros → `every(b => b === 0)` is true → assertion fails.
    // GREEN: sealWriteKey is NODE_WRITE_KEY (0xcc fill) → not all-zeros → passes.
    expect(sealWriteKey.every((b) => b === 0)).toBe(false);
    expect(sealWriteKey).toEqual(NODE_WRITE_KEY);
  });

  it('Test 3: sealNode receives a node whose writeBody.ipnsPrivateKey matches pre-rotation', async () => {
    // RED: unsealNode is called without writeKey → returns node WITHOUT writeBody →
    //      updatedNode.writeBody is undefined → sealNode receives a node with no writeBody.
    //      Assertion that sealedNode.writeBody is defined fails.
    // GREEN: unsealNode called WITH writeKey → returns node WITH writeBody →
    //        updatedNode.writeBody present → sealNode receives it unchanged → passes.

    // Override: simulate realistic behavior — only return writeBody when writeKey is provided
    mockFns.unsealNode.mockImplementation(
      async (
        _pub: import('@cipherbox/core').PublishedNode,
        _readKey: Uint8Array,
        writeKey?: Uint8Array
      ) => {
        if (writeKey && writeKey.some((b) => b !== 0)) {
          return makeNodeWithWriteBody();
        }
        return makeNodeWithoutWriteBody();
      }
    );

    const capturedSealNodes: import('@cipherbox/core').Node[] = [];
    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) => {
      capturedSealNodes.push(node);
      return makePublishedNodeWithWriteSealed(node.id, node.generation);
    });

    await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      nodeIpnsPrivateKey: NODE_IPNS_PRIVATE_KEY,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ...({ nodeWriteKey: NODE_WRITE_KEY } as any),
    }).catch(() => {});

    expect(capturedSealNodes.length).toBeGreaterThan(0);
    const sealedNode = capturedSealNodes[0];
    // RED: sealedNode.writeBody is undefined (write-body dropped) → fails.
    // GREEN: sealedNode.writeBody.ipnsPrivateKey equals IPNS_PRIVATE_KEY_IN_WRITE_BODY → passes.
    expect(sealedNode?.writeBody).toBeDefined();
    expect(sealedNode?.writeBody?.ipnsPrivateKey).toEqual(IPNS_PRIVATE_KEY_IN_WRITE_BODY);
  });

  it('Test 4: generation is bumped by 1 and readKey is rotated (read plane invariant)', async () => {
    // This should pass in GREEN — documents the read-plane rotation invariant.
    // It ALSO must pass after GREEN without regressing the existing read-only behavior.

    const result = await rotateOne({
      nodeId: NODE_ID,
      nodeIpnsName: NODE_IPNS,
      nodeIpnsPrivateKey: NODE_IPNS_PRIVATE_KEY,
      parentReadKey: PARENT_READ_KEY,
      parentIpnsName: PARENT_IPNS,
      parentCurrentSeq: 5n,
      jobRecord: makeJobRecord(),
      ctx: createMockContext(),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ...({ nodeWriteKey: NODE_WRITE_KEY } as any),
    });

    // unsealNode returns generation: 1, so generationPrime must be 2
    expect(result.newGeneration).toBe(2);
    // childReadKey must be a 32-byte buffer (fresh minted)
    expect(result.childReadKey).toBeInstanceOf(Uint8Array);
    expect(result.childReadKey.length).toBe(32);
  });
});

// ---------------------------------------------------------------------------
// Suite 2: Fail-closed — writeSealed present but no valid writeKey threaded
// ---------------------------------------------------------------------------

describe('rotateOne — fail-closed: writeSealed present without valid nodeWriteKey (Plan 65-05)', () => {
  beforeEach(() => {
    vi.resetAllMocks();

    const published = makePublishedNodeWithWriteSealed(NODE_ID, 1);
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'bafy-write-cid',
      sequenceNumber: 5n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(new TextEncoder().encode(JSON.stringify(published)));
    // Return node without writeBody (simulates current behavior — unseal without writeKey)
    mockFns.unsealNode.mockResolvedValue(makeNodeWithoutWriteBody());
    mockFns.sealNode.mockResolvedValue(makePublishedNodeWithWriteSealed(NODE_ID, 2));
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new-cid',
      newSequenceNumber: 6n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('Test 5: throws when published.writeSealed is set but nodeWriteKey is absent', async () => {
    // RED: no guard in the engine → rotateOne resolves silently (write-body silently dropped).
    //      `rejects.toThrow` assertion fails.
    // GREEN: fail-closed guard added → rejects with a message referencing writeKey.

    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: NODE_IPNS_PRIVATE_KEY,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 5n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
        // nodeWriteKey intentionally NOT provided
      })
    ).rejects.toThrow(/writeKey/i);
  });

  it('Test 6: throws when nodeWriteKey is all-zeros (placeholder is rejected)', async () => {
    // RED: no guard → resolves with all-zeros placeholder (corrupt write plane).
    // GREEN: all-zero writeKey is rejected by the fail-closed guard.

    await expect(
      rotateOne({
        nodeId: NODE_ID,
        nodeIpnsName: NODE_IPNS,
        nodeIpnsPrivateKey: NODE_IPNS_PRIVATE_KEY,
        parentReadKey: PARENT_READ_KEY,
        parentIpnsName: PARENT_IPNS,
        parentCurrentSeq: 5n,
        jobRecord: makeJobRecord(),
        ctx: createMockContext(),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ...({ nodeWriteKey: new Uint8Array(32) } as any), // all-zeros
      })
    ).rejects.toThrow(/writeKey/i);
  });
});

// ---------------------------------------------------------------------------
// Suite 3: rotateReadFromNode — nodeKeySource.writeKey wires through BFS
// ---------------------------------------------------------------------------

describe('rotateReadFromNode — nodeKeySource.writeKey threaded to rotateOne (Plan 65-05)', () => {
  const ROOT_READ_KEY = new Uint8Array(32).fill(0x77);
  const ROOT_IPNS_PRIVATE_KEY = new Uint8Array(32).fill(0x10);
  const CHILD_ID = 'child-1111-2222-3333-444444444444';
  const CHILD_IPNS = 'k51childwrite000000000000000000000000000000000000000000000000000';
  const CHILD_WRITE_KEY = new Uint8Array(32).fill(0xee);

  beforeEach(() => {
    vi.resetAllMocks();

    const rootPublished = makePublishedNodeWithWriteSealed(NODE_ID, 0);
    const childPublished = makePublishedNodeWithWriteSealed(CHILD_ID, 0);

    mockFns.resolveIpnsRecord.mockImplementation(async (ipnsName: string) => ({
      cid: ipnsName === NODE_IPNS ? 'bafy-root' : 'bafy-child',
      sequenceNumber: 1n,
      signatureVerified: true,
    }));

    mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
      const node = cid === 'bafy-root' ? rootPublished : childPublished;
      return new TextEncoder().encode(JSON.stringify(node));
    });

    const rootNode: import('@cipherbox/core').Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: NODE_ID,
      generation: 0,
      createdAt: 1000,
      modifiedAt: 2000,
      children: [
        {
          name: 'child',
          ipnsName: CHILD_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'childsealed==',
        },
      ],
      writeBody: {
        ipnsPrivateKey: new Uint8Array(IPNS_PRIVATE_KEY_IN_WRITE_BODY),
        writeChildren: [],
      },
    };

    const childNode: import('@cipherbox/core').Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: CHILD_ID,
      generation: 0,
      createdAt: 1000,
      modifiedAt: 2000,
      children: [],
      writeBody: {
        ipnsPrivateKey: new Uint8Array(IPNS_PRIVATE_KEY_IN_WRITE_BODY),
        writeChildren: [],
      },
    };

    // Return node with writeBody regardless of args (GREEN will thread writeKey so this matters)
    mockFns.unsealNode.mockImplementation(
      async (published: import('@cipherbox/core').PublishedNode) =>
        published.id === NODE_ID ? rootNode : childNode
    );

    mockFns.sealNode.mockImplementation(async (node: import('@cipherbox/core').Node) =>
      makePublishedNodeWithWriteSealed(node.id, node.generation + 1)
    );
    mockFns.sealChildReadKey.mockResolvedValue('newsealed==');
    mockFns.unsealChildReadKey.mockResolvedValue(new Uint8Array(32).fill(0x42));
    mockFns.publishWithCas.mockResolvedValue({
      cid: 'bafy-new',
      newSequenceNumber: 2n,
      publishedData: [],
      prunedCids: [],
    });
  });

  it('Test 7: nodeKeySource writeKey is passed to sealNode for each node in BFS', async () => {
    // RED: nodeKeySource.writeKey is ignored → sealNode receives all-zeros PLACEHOLDER_WRITE_KEY.
    //      Assertion that sealNode is NOT called with all-zeros fails.
    // GREEN: nodeKeySource.writeKey is threaded through rotateOne.nodeWriteKey →
    //        sealNode receives the real writeKey → assertion passes.

    const capturedSealWriteKeys: Uint8Array[] = [];
    mockFns.sealNode.mockImplementation(
      async (_node: import('@cipherbox/core').Node, _readKey: Uint8Array, writeKey: Uint8Array) => {
        capturedSealWriteKeys.push(new Uint8Array(writeKey)); // copy before any zeroing
        return makePublishedNodeWithWriteSealed(_node.id, _node.generation + 1);
      }
    );

    // No .catch(): in GREEN, rotateReadFromNode must complete without throwing.
    await rotateReadFromNode({
      rootNodeId: NODE_ID,
      rootNodeIpnsName: NODE_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootIpnsPrivateKey: ROOT_IPNS_PRIVATE_KEY,
      jobRecord: makeJobRecord({ rootNodeId: NODE_ID }),
      ctx: createMockContext(),
      nodeKeySource: (ipnsName: string) => {
        if (ipnsName === NODE_IPNS) {
          return {
            privateKey: ROOT_IPNS_PRIVATE_KEY,
            publicKey: new Uint8Array(32).fill(0x01),
            // writeKey for root (included — ignored in RED, used in GREEN)
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ...({ writeKey: NODE_WRITE_KEY } as any),
          };
        }
        if (ipnsName === CHILD_IPNS) {
          return {
            privateKey: new Uint8Array(32).fill(0x12),
            publicKey: new Uint8Array(32).fill(0x01),
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ...({ writeKey: CHILD_WRITE_KEY } as any),
          };
        }
        return undefined;
      },
    });

    // Must have captured one sealNode call per BFS node (root + child = 2).
    expect(capturedSealWriteKeys.length).toBeGreaterThanOrEqual(2);

    // GREEN: each captured write key matches the node-specific key supplied by nodeKeySource.
    // capturedSealWriteKeys contains COPIES made at call time, so zeroing originals won't affect them.
    expect(capturedSealWriteKeys).toEqual(
      expect.arrayContaining([NODE_WRITE_KEY, CHILD_WRITE_KEY])
    );
  });
});
