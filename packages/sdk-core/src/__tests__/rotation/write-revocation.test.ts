/**
 * Tests for rotateWriteFromNode — Write-revocation driver (WRITE-02/03/04).
 *
 * TDD RED phase — written before the implementation (65-06 Task 1).
 * Covers:
 *   - Per-node new k51 names (different from old names)
 *   - First-publish at sequenceNumber 1n for each new name
 *   - Child-first cascade (child published before root re-points)
 *   - teeUnenrollFn called for each old name (tombstone-intent)
 *   - Co-writer re-wrap via wrapKey and encryptedWriteKeyPersistFn (survivor)
 *   - Revoked grant dropped via deleteWriteGrantFn (not re-wrapped)
 *   - Read-plane invariance (no readKey rotation, no generation bump)
 *   - Parent SealedChildRef.ipnsName re-pointed to new child name
 *
 * Mock pattern: vi.hoisted + vi.mock (mirrors write-body-reseal.test.ts).
 * Transport seam: inject vi.fn() callbacks — no DB / API import needed (D-02).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { rotateWriteFromNode, type WriteRevocationCallbacks } from '../../rotation/engine';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks — hoisted before vi.mock() factories
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  // ipns
  resolveIpnsRecord: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
  batchPublishIpnsRecords: vi.fn(),
  // ipfs
  fetchFromIpfs: vi.fn(),
  addToIpfs: vi.fn(),
  // cas (unused by rotateWriteFromNode — included for completeness)
  publishWithCas: vi.fn(),
  // core seal
  unsealNode: vi.fn(),
  sealNode: vi.fn(),
  sealChildReadKey: vi.fn(),
  unsealChildReadKey: vi.fn(),
  sealChildWriteKey: vi.fn(),
  unsealChildWriteKey: vi.fn(),
  // crypto
  generateEd25519Keypair: vi.fn(),
  deriveIpnsName: vi.fn(),
  generateRandomBytes: vi.fn(),
  wrapKey: vi.fn(),
}));

vi.mock('../../ipns', () => ({
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  batchPublishIpnsRecords: mockFns.batchPublishIpnsRecords,
}));

vi.mock('../../ipfs', () => ({
  fetchFromIpfs: mockFns.fetchFromIpfs,
  addToIpfs: mockFns.addToIpfs,
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

// bytesToBase64/base64ToBytes are kept as the real implementation (importOriginal)
// since engine.ts now imports the shared codec from here too (Plan 77-08).
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    generateEd25519Keypair: mockFns.generateEd25519Keypair,
    deriveIpnsName: mockFns.deriveIpnsName,
    generateRandomBytes: mockFns.generateRandomBytes,
    wrapKey: mockFns.wrapKey,
    unwrapKey: vi.fn(),
    reWrapKey: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const ROOT_ID = 'root-aaaa-1111-bbbb-cccccccccccc';
const CHILD_ID = 'child-aaaa-2222-bbbb-cccccccccccc';

const OLD_ROOT_IPNS = 'k51oldroot000000000000000000000000000000000000000000000000000000';
const OLD_CHILD_IPNS = 'k51oldchld0000000000000000000000000000000000000000000000000000000';

const NEW_ROOT_IPNS = 'k51newroot000000000000000000000000000000000000000000000000000000';
const NEW_CHILD_IPNS = 'k51newchld0000000000000000000000000000000000000000000000000000000';

/** Root's read key — must never be rotated by rotateWriteFromNode (D-06). */
const ROOT_READ_KEY = new Uint8Array(32).fill(0xaa);
/** Root's old write key supplied by the caller. */
const ROOT_WRITE_KEY = new Uint8Array(32).fill(0xbb);
/** Child's derived read key (from unsealChildReadKey). */
const CHILD_READ_KEY = new Uint8Array(32).fill(0xcc);
/** Child's derived write key (from unsealChildWriteKey). */
const CHILD_WRITE_KEY = new Uint8Array(32).fill(0xdd);

/** New write keys MINTED by rotateWriteFromNode. */
const NEW_CHILD_WRITE_KEY = new Uint8Array(32).fill(0x22);
const NEW_ROOT_WRITE_KEY = new Uint8Array(32).fill(0x11);

/** New Ed25519 keypairs MINTED by rotateWriteFromNode (child-first order). */
const NEW_CHILD_IPNS_PRIV = new Uint8Array(32).fill(0x55);
const NEW_CHILD_IPNS_PUB = new Uint8Array(32).fill(0x56);
const NEW_ROOT_IPNS_PRIV = new Uint8Array(32).fill(0x33);
const NEW_ROOT_IPNS_PUB = new Uint8Array(32).fill(0x34);

/** Old IPNS private keys stored inside write bodies (before rotation). */
const OLD_ROOT_IPNS_PRIV = new Uint8Array(32).fill(0x77);
const OLD_CHILD_IPNS_PRIV = new Uint8Array(32).fill(0x88);

const WRITE_KEY_SEALED_CHILD_IN_ROOT = 'old-child-write-key-sealed-base64-placeholder';
const READ_KEY_SEALED_CHILD_IN_ROOT = 'old-child-read-key-sealed-base64-placeholder';

/** Sealed write key for child under the NEW root write key (mock result of sealChildWriteKey). */
const SEALED_CHILD_WRITE_KEY_UNDER_NEW_ROOT = 'new-child-write-key-sealed-under-new-root-write-key';

// Grant fixtures
const SHARE_ID_SURVIVOR = 'share-survivor-aaaa-1111';
const SHARE_ID_REVOKED = 'share-revoked-bbbb-2222';
const SURVIVOR_PUB_KEY = new Uint8Array(65).fill(0x01);
SURVIVOR_PUB_KEY[0] = 0x04; // uncompressed secp256k1 prefix
const REVOKED_PUB_KEY = new Uint8Array(65).fill(0x02);
REVOKED_PUB_KEY[0] = 0x04;

/** Simulated wrapped bytes returned by wrapKey. */
const MOCK_WRAPPED_BYTES = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
/** Expected base64 encoding of MOCK_WRAPPED_BYTES. */
const EXPECTED_ENCRYPTED_KEY = btoa(String.fromCharCode(0xde, 0xad, 0xbe, 0xef));

// ---------------------------------------------------------------------------
// Node fixtures (returned by mocked unsealNode)
// ---------------------------------------------------------------------------

const ROOT_NODE = {
  schema: 'node/v3' as const,
  kind: 'folder' as const,
  id: ROOT_ID,
  generation: 5,
  createdAt: 1000,
  modifiedAt: 2000,
  children: [
    {
      name: 'subfolder1',
      ipnsName: OLD_CHILD_IPNS,
      generation: 0,
      versionFloor: 1n,
      readKeySealed: READ_KEY_SEALED_CHILD_IN_ROOT,
    },
  ],
  writeBody: {
    ipnsPrivateKey: OLD_ROOT_IPNS_PRIV,
    writeChildren: [{ childId: CHILD_ID, writeKeySealed: WRITE_KEY_SEALED_CHILD_IN_ROOT }],
  },
};

const CHILD_NODE = {
  schema: 'node/v3' as const,
  kind: 'folder' as const,
  id: CHILD_ID,
  generation: 0,
  createdAt: 3000,
  modifiedAt: 4000,
  children: [],
  writeBody: {
    ipnsPrivateKey: OLD_CHILD_IPNS_PRIV,
    writeChildren: [],
  },
};

/** Plaintext envelope fields for published nodes (real sealed fields not needed — unsealNode is mocked). */
const ROOT_PUB = {
  schema: 'node/v3',
  kind: 'folder',
  id: ROOT_ID,
  generation: 5,
  aeadVersion: 1,
  readSealed: 'root-read-sealed-placeholder',
  writeSealed: 'root-write-sealed-placeholder',
};

const CHILD_PUB = {
  schema: 'node/v3',
  kind: 'folder',
  id: CHILD_ID,
  generation: 0,
  aeadVersion: 1,
  readSealed: 'child-read-sealed-placeholder',
  writeSealed: 'child-write-sealed-placeholder',
};

// ---------------------------------------------------------------------------
// Helper: build a WriteRevocationCallbacks with vi.fn() defaults
// ---------------------------------------------------------------------------

function makeCallbacks(overrides?: Partial<WriteRevocationCallbacks>): WriteRevocationCallbacks {
  return {
    queryWriteGrantsFn: vi.fn().mockResolvedValue([
      { shareId: SHARE_ID_SURVIVOR, recipientPublicKey: SURVIVOR_PUB_KEY, isRevoked: false },
      { shareId: SHARE_ID_REVOKED, recipientPublicKey: REVOKED_PUB_KEY, isRevoked: true },
    ]),
    encryptedWriteKeyPersistFn: vi.fn().mockResolvedValue(undefined),
    teeUnenrollFn: vi.fn().mockResolvedValue(undefined),
    deleteWriteGrantFn: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Shared mock setup (reset in beforeEach)
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();

  // IPNS resolve: old names → existing CIDs
  mockFns.resolveIpnsRecord.mockImplementation(async (name: string) => {
    if (name === OLD_ROOT_IPNS) return { cid: 'bafyRootOld', sequenceNumber: 5n };
    if (name === OLD_CHILD_IPNS) return { cid: 'bafyChildOld', sequenceNumber: 3n };
    return null;
  });

  // IPFS fetch: return serialized published envelopes
  mockFns.fetchFromIpfs.mockImplementation(async (_ctx: unknown, cid: string) => {
    if (cid === 'bafyRootOld') return new TextEncoder().encode(JSON.stringify(ROOT_PUB));
    if (cid === 'bafyChildOld') return new TextEncoder().encode(JSON.stringify(CHILD_PUB));
    return new Uint8Array(0);
  });

  // unsealNode: root first (enumeration), child second (leaf processing)
  mockFns.unsealNode.mockResolvedValueOnce(ROOT_NODE).mockResolvedValueOnce(CHILD_NODE);

  // unsealChildReadKey: returns child's read key (used to re-seal child's read-body)
  mockFns.unsealChildReadKey.mockResolvedValue(CHILD_READ_KEY);

  // unsealChildWriteKey: returns child's write key (used to traverse child's write-body)
  mockFns.unsealChildWriteKey.mockResolvedValue(CHILD_WRITE_KEY);

  // generateEd25519Keypair: child first (bottom-up), then root.
  // Return fresh copies so the engine's fill(0) zeroisation of minted private keys
  // does not mutate the shared fixture constants and pollute subsequent tests (#5).
  mockFns.generateEd25519Keypair
    .mockReturnValueOnce({
      privateKey: new Uint8Array(NEW_CHILD_IPNS_PRIV),
      publicKey: new Uint8Array(NEW_CHILD_IPNS_PUB),
    })
    .mockReturnValueOnce({
      privateKey: new Uint8Array(NEW_ROOT_IPNS_PRIV),
      publicKey: new Uint8Array(NEW_ROOT_IPNS_PUB),
    });

  // deriveIpnsName: new k51 names from new public keys (child first, then root)
  mockFns.deriveIpnsName.mockResolvedValueOnce(NEW_CHILD_IPNS).mockResolvedValueOnce(NEW_ROOT_IPNS);

  // generateRandomBytes: new write keys (child first, then root).
  // Return fresh copies so the engine's fill(0) does not corrupt the fixture constants (#5).
  mockFns.generateRandomBytes
    .mockReturnValueOnce(new Uint8Array(NEW_CHILD_WRITE_KEY))
    .mockReturnValueOnce(new Uint8Array(NEW_ROOT_WRITE_KEY));

  // sealNode: returns minimal sealed envelopes (content not checked here)
  mockFns.sealNode.mockResolvedValue({
    schema: 'node/v3',
    kind: 'folder',
    id: 'mock-sealed-node',
    generation: 0,
    aeadVersion: 1,
    readSealed: 'new-read-sealed',
    writeSealed: 'new-write-sealed',
  });

  // sealChildWriteKey: returns sealed ref for child write key under new parent write key
  mockFns.sealChildWriteKey.mockResolvedValue(SEALED_CHILD_WRITE_KEY_UNDER_NEW_ROOT);

  // addToIpfs: returns a mock CID
  mockFns.addToIpfs.mockResolvedValue({ cid: 'bafyNewNode' });

  // createAndPublishIpnsRecord: success
  mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 1n });

  // wrapKey: returns mock wrapped bytes for co-writer encrypted key
  mockFns.wrapKey.mockResolvedValue(MOCK_WRAPPED_BYTES);
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('rotateWriteFromNode', () => {
  it('Test 1: mints a new Ed25519 keypair and k51 name for each node in the subtree', async () => {
    const ctx = createMockContext();
    const callbacks = makeCallbacks();

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    // One new keypair per node (child + root = 2)
    expect(mockFns.generateEd25519Keypair).toHaveBeenCalledTimes(2);
    // One new k51 name derived per keypair
    expect(mockFns.deriveIpnsName).toHaveBeenCalledTimes(2);
    // One new writeKey per node
    expect(mockFns.generateRandomBytes).toHaveBeenCalledTimes(2);
    expect(mockFns.generateRandomBytes).toHaveBeenCalledWith(32);
  });

  it('Test 2: each new k51 name is first-published at sequenceNumber 1n', async () => {
    const ctx = createMockContext();
    const callbacks = makeCallbacks();

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    // Two new names published (child + root)
    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledTimes(2);

    // Both publishes must carry sequenceNumber: 1n (strict gate)
    const calls = mockFns.createAndPublishIpnsRecord.mock.calls as Array<
      [{ sequenceNumber: bigint; ipnsName: string }]
    >;
    for (const [params] of calls) {
      expect(params.sequenceNumber).toBe(1n);
    }

    // New names must differ from old names
    const publishedNames = calls.map(([p]) => p.ipnsName);
    expect(publishedNames).not.toContain(OLD_ROOT_IPNS);
    expect(publishedNames).not.toContain(OLD_CHILD_IPNS);
    expect(publishedNames).toContain(NEW_CHILD_IPNS);
    expect(publishedNames).toContain(NEW_ROOT_IPNS);
  });

  it('Test 3: child-first cascade — child new name is published before root new name', async () => {
    const ctx = createMockContext();
    const callOrder: string[] = [];

    const teeUnenrollFn = vi.fn().mockImplementation(async (name: string) => {
      callOrder.push(`unenroll:${name}`);
    });

    mockFns.createAndPublishIpnsRecord.mockImplementation(async (params: { ipnsName: string }) => {
      callOrder.push(`publish:${params.ipnsName}`);
      return { success: true, sequenceNumber: 1n };
    });

    const callbacks = makeCallbacks({ teeUnenrollFn });

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    const childPublishIdx = callOrder.indexOf(`publish:${NEW_CHILD_IPNS}`);
    const rootPublishIdx = callOrder.indexOf(`publish:${NEW_ROOT_IPNS}`);

    // Child-first: child's new name published before root's new name
    expect(childPublishIdx).toBeGreaterThanOrEqual(0);
    expect(rootPublishIdx).toBeGreaterThanOrEqual(0);
    expect(childPublishIdx).toBeLessThan(rootPublishIdx);
  });

  it('Test 4: teeUnenrollFn is called once per old IPNS name (tombstone-intent)', async () => {
    const ctx = createMockContext();
    const callbacks = makeCallbacks();

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    // Both old names tombstoned
    expect(callbacks.teeUnenrollFn).toHaveBeenCalledWith(OLD_CHILD_IPNS);
    expect(callbacks.teeUnenrollFn).toHaveBeenCalledWith(OLD_ROOT_IPNS);
    expect(callbacks.teeUnenrollFn).toHaveBeenCalledTimes(2);
  });

  it('Test 5: queryWriteGrantsFn is called with the root node ID', async () => {
    const ctx = createMockContext();
    const callbacks = makeCallbacks();

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    expect(callbacks.queryWriteGrantsFn).toHaveBeenCalledWith(ROOT_ID);
    expect(callbacks.queryWriteGrantsFn).toHaveBeenCalledTimes(1);
  });

  it('Test 6: survivor gets new encryptedWriteKey via wrapKey; revoked recipient is dropped', async () => {
    const ctx = createMockContext();
    const callbacks = makeCallbacks();

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    // wrapKey called once: new root write key wrapped for survivor
    expect(mockFns.wrapKey).toHaveBeenCalledTimes(1);
    expect(mockFns.wrapKey).toHaveBeenCalledWith(expect.any(Uint8Array), SURVIVOR_PUB_KEY);

    // Survivor gets encryptedWriteKeyPersistFn with base64(wrappedBytes)
    expect(callbacks.encryptedWriteKeyPersistFn).toHaveBeenCalledWith(
      SHARE_ID_SURVIVOR,
      EXPECTED_ENCRYPTED_KEY
    );
    expect(callbacks.encryptedWriteKeyPersistFn).toHaveBeenCalledTimes(1);

    // Revoked recipient is dropped — never re-wrapped
    expect(callbacks.deleteWriteGrantFn).toHaveBeenCalledWith(SHARE_ID_REVOKED);
    expect(callbacks.deleteWriteGrantFn).toHaveBeenCalledTimes(1);

    // Revoked recipient must NOT get an encrypted key
    expect(callbacks.encryptedWriteKeyPersistFn).not.toHaveBeenCalledWith(
      SHARE_ID_REVOKED,
      expect.anything()
    );
  });

  it('Test 7: read plane is invariant — no generation bump, no new readKey', async () => {
    const ctx = createMockContext();
    const callbacks = makeCallbacks();

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    // sealNode called for both child and root
    expect(mockFns.sealNode).toHaveBeenCalledTimes(2);

    const sealNodeCalls = mockFns.sealNode.mock.calls as Array<
      [{ id: string; generation: number }, Uint8Array, Uint8Array]
    >;

    // Root: generation must NOT be bumped (still 5, not 6)
    const rootCall = sealNodeCalls.find(([node]) => node.id === ROOT_ID);
    expect(rootCall).toBeDefined();
    expect(rootCall![0].generation).toBe(ROOT_NODE.generation); // 5

    // Child: generation must NOT be bumped (still 0, not 1)
    const childCall = sealNodeCalls.find(([node]) => node.id === CHILD_ID);
    expect(childCall).toBeDefined();
    expect(childCall![0].generation).toBe(CHILD_NODE.generation); // 0

    // generateRandomBytes called EXACTLY twice (2 write keys) — no readKeys minted
    expect(mockFns.generateRandomBytes).toHaveBeenCalledTimes(2);
  });

  it('Test 8: parent SealedChildRef.ipnsName is re-pointed to the child new name', async () => {
    const ctx = createMockContext();
    const callbacks = makeCallbacks();

    // Capture fresh copies of sealChildWriteKey arguments — the engine zeroes the child
    // write key buffer after sealing (D-09 / #2), so mock.calls[0][0] would be all-zeros
    // by the time assertions run if we read the reference directly.
    const capturedSealChildArgs: [Uint8Array, Uint8Array, string, string, number][] = [];
    mockFns.sealChildWriteKey.mockImplementation(
      async (
        childWriteKey: Uint8Array,
        parentWriteKey: Uint8Array,
        childId: string,
        kind: string,
        generation: number
      ) => {
        capturedSealChildArgs.push([
          new Uint8Array(childWriteKey),
          new Uint8Array(parentWriteKey),
          childId,
          kind,
          generation,
        ]);
        return SEALED_CHILD_WRITE_KEY_UNDER_NEW_ROOT;
      }
    );

    await rotateWriteFromNode({
      rootNodeId: ROOT_ID,
      rootIpnsName: OLD_ROOT_IPNS,
      rootReadKey: ROOT_READ_KEY,
      rootWriteKey: ROOT_WRITE_KEY,
      ctx,
      callbacks,
    });

    const sealNodeCalls = mockFns.sealNode.mock.calls as Array<
      [
        {
          id: string;
          children?: Array<{ ipnsName: string }>;
          writeBody?: { writeChildren: Array<{ writeKeySealed: string }> };
        },
        Uint8Array,
        Uint8Array,
      ]
    >;

    // The root node sealed by sealNode must have children[0].ipnsName = NEW_CHILD_IPNS
    const rootCall = sealNodeCalls.find(([node]) => node.id === ROOT_ID);
    expect(rootCall).toBeDefined();
    const sealedRoot = rootCall![0];
    expect(sealedRoot.children).toBeDefined();
    expect(sealedRoot.children![0].ipnsName).toBe(NEW_CHILD_IPNS);

    // The write-body's writeChildren must reference the new child write key sealed
    // under the new parent write key (via sealChildWriteKey)
    expect(capturedSealChildArgs.length).toBe(1);

    // Verify sealChildWriteKey received the correct arguments.
    // arg[0]: child's new write key — captured before engine's fill(0) (D-09 / #2)
    // arg[1]: parent's new write key (32-byte Uint8Array — also zeroed after use)
    // arg[2..4]: child id / kind / generation for AAD binding
    const sealChildArgs = capturedSealChildArgs[0]!;
    expect(sealChildArgs[0]).toEqual(NEW_CHILD_WRITE_KEY); // child write key sealed under parent
    expect(sealChildArgs[1]).toBeInstanceOf(Uint8Array);
    expect(sealChildArgs[1].length).toBe(32); // parent write key
    expect(sealChildArgs[2]).toBe(CHILD_ID);
    expect(sealChildArgs[3]).toBe(CHILD_NODE.kind);
    expect(sealChildArgs[4]).toBe(CHILD_NODE.generation);

    // The sealed write key must appear in the root's writeBody.writeChildren
    expect(sealedRoot.writeBody?.writeChildren[0]?.writeKeySealed).toBe(
      SEALED_CHILD_WRITE_KEY_UNDER_NEW_ROOT
    );
  });
});
