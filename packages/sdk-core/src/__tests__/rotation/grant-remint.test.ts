/**
 * Tests for reMintGrantsRootedAt (ROT-04 / HIGH-3 / D-04)
 *
 * TDD RED phase — written before the implementation is filled.
 * Covers: non-revoked re-mint, revoked delete, mixed set, and no-callbacks no-op.
 *
 * Mock pattern: vi.hoisted + vi.mock (mirrors engine.test.ts analog).
 * Transport seam: inject vi.fn() callbacks — no DB / API import needed.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { reMintGrantsRootedAt, type RotationJobRecord } from '../../rotation/engine';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks — hoisted before vi.mock() factories
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  wrapKey: vi.fn(),
}));

// Mock @cipherbox/crypto to intercept wrapKey (ECIES encrypted-key minting).
// engine.ts imports wrapKey from this package in the GREEN phase.
vi.mock('@cipherbox/crypto', () => ({
  wrapKey: mockFns.wrapKey,
  generateRandomBytes: vi.fn(),
  unwrapKey: vi.fn(),
  reWrapKey: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const NODE_ID = 'node-aaaa-1111-bbbb-cccccccccccc';
const NEW_READ_KEY = new Uint8Array(32).fill(0xab);
const NEW_GENERATION = 3;

/** Simulated 4-byte wrapped key returned by the mock wrapKey. */
const MOCK_WRAPPED_BYTES = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

/** Expected base64 encoding of MOCK_WRAPPED_BYTES (what updateGrantFn receives). */
const EXPECTED_ENCRYPTED_KEY = btoa(String.fromCharCode(0xde, 0xad, 0xbe, 0xef));

const SHARE_ID_A = 'share-aaaa-1111';
const SHARE_ID_B = 'share-bbbb-2222';

const RECIPIENT_PUB_KEY_A = new Uint8Array(65).fill(0x01);
RECIPIENT_PUB_KEY_A[0] = 0x04; // uncompressed secp256k1 prefix
const RECIPIENT_PUB_KEY_B = new Uint8Array(65).fill(0x02);
RECIPIENT_PUB_KEY_B[0] = 0x04;

function makeJobRecord(overrides?: Partial<RotationJobRecord>): RotationJobRecord {
  return {
    rootNodeId: NODE_ID,
    status: 'in-progress',
    completedNodeIds: new Set(),
    frontier: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('reMintGrantsRootedAt', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.wrapKey.mockResolvedValue(MOCK_WRAPPED_BYTES);
  });

  it('Test 1: re-mints encryptedReadKey for a non-revoked grant via ECIES', async () => {
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
      queryGrantsFn: mockQueryGrants,
      updateGrantFn: mockUpdateGrant,
      deleteGrantFn: mockDeleteGrant,
    });

    // queryGrantsFn must be called with the rotated nodeId
    expect(mockQueryGrants).toHaveBeenCalledWith(NODE_ID);

    // wrapKey must be called with (newReadKey, recipientPublicKey) — ECIES wrap
    expect(mockFns.wrapKey).toHaveBeenCalledWith(NEW_READ_KEY, RECIPIENT_PUB_KEY_A);

    // updateGrantFn must be called with (shareId, base64EncryptedKey, newGeneration)
    expect(mockUpdateGrant).toHaveBeenCalledWith(
      SHARE_ID_A,
      EXPECTED_ENCRYPTED_KEY,
      NEW_GENERATION
    );
    expect(mockUpdateGrant).toHaveBeenCalledTimes(1);

    // deleteGrantFn must NOT be called (grant is not revoked)
    expect(mockDeleteGrant).not.toHaveBeenCalled();
  });

  it('Test 2: deletes revoked recipient grant row without re-minting encrypted key', async () => {
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_B, recipientPublicKey: RECIPIENT_PUB_KEY_B, isRevoked: true },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
      queryGrantsFn: mockQueryGrants,
      updateGrantFn: mockUpdateGrant,
      deleteGrantFn: mockDeleteGrant,
    });

    // deleteGrantFn must be called for the revoked recipient
    expect(mockDeleteGrant).toHaveBeenCalledWith(SHARE_ID_B);
    expect(mockDeleteGrant).toHaveBeenCalledTimes(1);

    // updateGrantFn and wrapKey must NOT be called for revoked recipients
    expect(mockUpdateGrant).not.toHaveBeenCalled();
    expect(mockFns.wrapKey).not.toHaveBeenCalled();
  });

  it('Test 3: handles a mixed set — exactly one update and one delete with correct shareIds', async () => {
    const mockQueryGrants = vi.fn().mockResolvedValue([
      { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      { shareId: SHARE_ID_B, recipientPublicKey: RECIPIENT_PUB_KEY_B, isRevoked: true },
    ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
      queryGrantsFn: mockQueryGrants,
      updateGrantFn: mockUpdateGrant,
      deleteGrantFn: mockDeleteGrant,
    });

    // Exactly one update (non-revoked) and one delete (revoked)
    expect(mockUpdateGrant).toHaveBeenCalledTimes(1);
    expect(mockUpdateGrant).toHaveBeenCalledWith(
      SHARE_ID_A,
      EXPECTED_ENCRYPTED_KEY,
      NEW_GENERATION
    );
    expect(mockUpdateGrant).not.toHaveBeenCalledWith(
      SHARE_ID_B,
      expect.anything(),
      expect.anything()
    );

    expect(mockDeleteGrant).toHaveBeenCalledTimes(1);
    expect(mockDeleteGrant).toHaveBeenCalledWith(SHARE_ID_B);
    expect(mockDeleteGrant).not.toHaveBeenCalledWith(SHARE_ID_A);
  });

  it('Test 4: is a clean no-op when no callbacks are supplied', async () => {
    const ctx = createMockContext();
    const job = makeJobRecord();

    // Must not throw even though the function is called without callbacks
    await expect(
      reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx)
    ).resolves.toBeUndefined();

    // No crypto operations should have run
    expect(mockFns.wrapKey).not.toHaveBeenCalled();
  });
});
