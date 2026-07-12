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
// bytesToBase64/base64ToBytes are kept as the real implementation (importOriginal)
// since engine.ts now imports the shared codec from here too (Plan 77-08).
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    wrapKey: mockFns.wrapKey,
    generateRandomBytes: vi.fn(),
    unwrapKey: vi.fn(),
    reWrapKey: vi.fn(),
  };
});

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
    const mockGetPins = vi.fn().mockResolvedValue([RECIPIENT_PUB_KEY_A]);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
      queryGrantsFn: mockQueryGrants,
      updateGrantFn: mockUpdateGrant,
      deleteGrantFn: mockDeleteGrant,
      getPinsFn: mockGetPins,
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
    const mockGetPins = vi.fn().mockResolvedValue([RECIPIENT_PUB_KEY_A]);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
      queryGrantsFn: mockQueryGrants,
      updateGrantFn: mockUpdateGrant,
      deleteGrantFn: mockDeleteGrant,
      getPinsFn: mockGetPins,
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

  // -------------------------------------------------------------------------
  // D-03d consumer 2 (TS re-mint) — fail-closed recipient-pin enforcement.
  //
  // reMintGrantsRootedAt must verify grant.recipientPublicKey (which round-trips
  // through the untrusted relay via listSentGrants) against the node's
  // owner-sealed recipientPins BEFORE wrapKey. A relay-substituted recipient
  // (mismatch) or an absent/empty pin list (D-03e no-legacy) is a HARD fail —
  // it throws and aborts the node's re-mint, unlike the per-grant isRevoked skip.
  // -------------------------------------------------------------------------

  it('Test A (D-03d mismatch): throws and does NOT wrap when getPinsFn omits the grant recipient', async () => {
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    // Pins list contains a DIFFERENT recipient (relay substituted the pubkey).
    const mockGetPins = vi.fn().mockResolvedValue([RECIPIENT_PUB_KEY_B]);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await expect(
      reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
        queryGrantsFn: mockQueryGrants,
        updateGrantFn: mockUpdateGrant,
        deleteGrantFn: mockDeleteGrant,
        getPinsFn: mockGetPins,
      })
    ).rejects.toThrow(/pinned/i);

    // Fail-closed: the read key was never wrapped to the substituted recipient.
    expect(mockFns.wrapKey).not.toHaveBeenCalled();
    expect(mockUpdateGrant).not.toHaveBeenCalled();
  });

  it('Test B (D-03e absent): throws when getPinsFn returns an empty pin list', async () => {
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const mockGetPins = vi.fn().mockResolvedValue([]);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await expect(
      reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
        queryGrantsFn: mockQueryGrants,
        updateGrantFn: mockUpdateGrant,
        deleteGrantFn: mockDeleteGrant,
        getPinsFn: mockGetPins,
      })
    ).rejects.toThrow();

    expect(mockFns.wrapKey).not.toHaveBeenCalled();
    expect(mockUpdateGrant).not.toHaveBeenCalled();
  });

  it('Test B2 (D-03e absent seam): throws when getPinsFn is missing for a surviving grant', async () => {
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await expect(
      reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
        queryGrantsFn: mockQueryGrants,
        updateGrantFn: mockUpdateGrant,
        deleteGrantFn: mockDeleteGrant,
      })
    ).rejects.toThrow();

    expect(mockFns.wrapKey).not.toHaveBeenCalled();
    expect(mockUpdateGrant).not.toHaveBeenCalled();
  });

  it('Test F (file carve-out): a file-rooted grant re-mints WITHOUT any pin check', async () => {
    // A shared FILE has no NodeWriteBody, so it can never carry an owner-sealed
    // pin. Passing nodeKind='file' must EXEMPT it from the D-03e 0-pins fail-
    // closed check (which would otherwise abort every rotation of a folder that
    // contains a separately-shared file). No getPinsFn is supplied, and an empty
    // pin source must NOT throw for a file.
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const mockGetPins = vi.fn().mockResolvedValue([]);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await reMintGrantsRootedAt(
      NODE_ID,
      NEW_READ_KEY,
      NEW_GENERATION,
      job,
      ctx,
      {
        queryGrantsFn: mockQueryGrants,
        updateGrantFn: mockUpdateGrant,
        deleteGrantFn: mockDeleteGrant,
        getPinsFn: mockGetPins,
      },
      'file'
    );

    // The pin seam is NOT consulted for a file, and the grant is re-minted.
    expect(mockGetPins).not.toHaveBeenCalled();
    expect(mockFns.wrapKey).toHaveBeenCalledWith(NEW_READ_KEY, RECIPIENT_PUB_KEY_A);
    expect(mockUpdateGrant).toHaveBeenCalledWith(
      SHARE_ID_A,
      EXPECTED_ENCRYPTED_KEY,
      NEW_GENERATION
    );
  });

  it('Test F2 (folder still enforced): a folder-rooted grant with empty pins still throws', async () => {
    // Contrast to Test F: the carve-out is file-only. A FOLDER (nodeKind
    // defaulted/absent) with an empty pin list stays fully fail-closed.
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const mockGetPins = vi.fn().mockResolvedValue([]);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await expect(
      reMintGrantsRootedAt(
        NODE_ID,
        NEW_READ_KEY,
        NEW_GENERATION,
        job,
        ctx,
        {
          queryGrantsFn: mockQueryGrants,
          updateGrantFn: mockUpdateGrant,
          deleteGrantFn: mockDeleteGrant,
          getPinsFn: mockGetPins,
        },
        'folder'
      )
    ).rejects.toThrow();
    expect(mockUpdateGrant).not.toHaveBeenCalled();
  });

  it('Test C (match): proceeds and wraps when getPinsFn includes the grant recipient', async () => {
    const mockQueryGrants = vi
      .fn()
      .mockResolvedValue([
        { shareId: SHARE_ID_A, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
      ]);
    const mockUpdateGrant = vi.fn().mockResolvedValue(undefined);
    const mockDeleteGrant = vi.fn().mockResolvedValue(undefined);
    const mockGetPins = vi.fn().mockResolvedValue([RECIPIENT_PUB_KEY_A]);
    const ctx = createMockContext();
    const job = makeJobRecord();

    await reMintGrantsRootedAt(NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, {
      queryGrantsFn: mockQueryGrants,
      updateGrantFn: mockUpdateGrant,
      deleteGrantFn: mockDeleteGrant,
      getPinsFn: mockGetPins,
    });

    // Pins fetched once for the node, recipient verified, then wrapped as before.
    expect(mockGetPins).toHaveBeenCalledWith(NODE_ID);
    expect(mockFns.wrapKey).toHaveBeenCalledWith(NEW_READ_KEY, RECIPIENT_PUB_KEY_A);
    expect(mockUpdateGrant).toHaveBeenCalledWith(
      SHARE_ID_A,
      EXPECTED_ENCRYPTED_KEY,
      NEW_GENERATION
    );
  });
});
