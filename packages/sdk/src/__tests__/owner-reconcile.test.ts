/**
 * Tests for the SDK owner-reconcile driver (D-10/D-11, mirrors Phase 65 D-01/Q3).
 *
 * TDD RED phase — written before the implementation is filled.
 *
 * Covers:
 *  - queryGrantsFn(nodeId) filters transport.listSentGrants() by rootNodeId
 *  - revoked grant -> transport.deleteGrant only (transport.updateGrant NOT called)
 *  - surviving grant -> transport.updateGrant only (transport.deleteGrant NOT called)
 *  - no recipient advisory is emitted (the transport has no notification method)
 *
 * Transport seam: inject vi.fn() mocks — no api-client / DB import needed.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { RotationJobRecord, SdkContext } from '@cipherbox/sdk-core';
import {
  buildGrantRemintCallbacks,
  runOwnerReconcile,
  type OwnerReconcileTransport,
  type GrantRow,
} from '../share/owner-reconcile';

// ---------------------------------------------------------------------------
// Module mocks — @cipherbox/crypto's wrapKey is invoked by the underlying
// sdk-core reMintGrantsRootedAt for surviving (non-revoked) grants.
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  wrapKey: vi.fn(),
}));

// Keep the real base64ToBytes/hexToBytes (via importOriginal) — the rebuilt
// sdk-core's assertRecipientPinned (80-04) decodes the pin list with them when
// verifying each surviving grant's recipient before wrapKey (D-03d consumer 2).
// Only the ECIES/randomness surface is stubbed; bytesToBase64 keeps its
// deterministic btoa form for the recipient pin list.
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    wrapKey: mockFns.wrapKey,
    generateRandomBytes: vi.fn(),
    unwrapKey: vi.fn(),
    reWrapKey: vi.fn(),
    bytesToBase64: vi.fn((bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))),
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ROOT_NODE_ID = 'node-aaaa-1111-bbbb-cccccccccccc';
const OTHER_NODE_ID = 'node-ffff-9999-eeee-dddddddddddd';
const NEW_READ_KEY = new Uint8Array(32).fill(0xab);
const NEW_GENERATION = 3;

const MOCK_WRAPPED_BYTES = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
// Hex, not base64 — reMintGrantsRootedAt encodes the wrapped read key with
// bytesToHex to match the grant API (Gap C fix).
const EXPECTED_ENCRYPTED_KEY = 'deadbeef';

const SHARE_ID_SURVIVING = 'share-survive-1111';
const SHARE_ID_REVOKED = 'share-revoked-2222';
const SHARE_ID_OTHER_ROOT = 'share-otherroot-3333';

const RECIPIENT_PUB_KEY_A = new Uint8Array(65).fill(0x01);
RECIPIENT_PUB_KEY_A[0] = 0x04;
const RECIPIENT_PUB_KEY_B = new Uint8Array(65).fill(0x02);
RECIPIENT_PUB_KEY_B[0] = 0x04;

function makeJobRecord(overrides?: Partial<RotationJobRecord>): RotationJobRecord {
  return {
    rootNodeId: ROOT_NODE_ID,
    status: 'in-progress',
    completedNodeIds: new Set(),
    frontier: [],
    ...overrides,
  };
}

function makeCtx(): SdkContext {
  return {
    apiUrl: 'http://localhost:3000',
    getAccessToken: vi.fn().mockResolvedValue('test-token'),
  };
}

function makeTransport(
  grants: GrantRow[],
  pins?: Uint8Array[]
): OwnerReconcileTransport & {
  listSentGrants: ReturnType<typeof vi.fn>;
  updateGrant: ReturnType<typeof vi.fn>;
  deleteGrant: ReturnType<typeof vi.fn>;
  getRecipientPubkeyPins: ReturnType<typeof vi.fn>;
} {
  // Default the owner-sealed pin list to the recipients of the supplied grants,
  // so a surviving grant is pinned unless a test overrides `pins` to force a
  // relay-substitution mismatch (D-03d) or an absent pin list (D-03e).
  const defaultPins = pins ?? grants.map((grant) => grant.recipientPublicKey);
  return {
    listSentGrants: vi.fn().mockResolvedValue(grants),
    updateGrant: vi.fn().mockResolvedValue(undefined),
    deleteGrant: vi.fn().mockResolvedValue(undefined),
    getRecipientPubkeyPins: vi.fn().mockResolvedValue(defaultPins),
  };
}

describe('buildGrantRemintCallbacks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.wrapKey.mockResolvedValue(MOCK_WRAPPED_BYTES);
  });

  it('Test 1: queryGrantsFn filters transport.listSentGrants() by rootNodeId', async () => {
    const transport = makeTransport([
      {
        shareId: SHARE_ID_SURVIVING,
        recipientPublicKey: RECIPIENT_PUB_KEY_A,
        isRevoked: false,
        rootNodeId: ROOT_NODE_ID,
      },
      {
        shareId: SHARE_ID_OTHER_ROOT,
        recipientPublicKey: RECIPIENT_PUB_KEY_B,
        isRevoked: false,
        rootNodeId: OTHER_NODE_ID,
      },
    ]);
    const callbacks = buildGrantRemintCallbacks(transport);

    const result = await callbacks.queryGrantsFn(ROOT_NODE_ID);

    expect(transport.listSentGrants).toHaveBeenCalledTimes(1);
    expect(result).toEqual([
      { shareId: SHARE_ID_SURVIVING, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
    ]);
  });

  // D-02 (TS mirror, Plan 80-03 / SC2-perf / T-80-09): queryGrantsFn is invoked
  // once per rotated node during a reconcile pass. Without a per-pass memo, each
  // call re-fetches transport.listSentGrants() → O(nodes × shares) relay fetches.
  // The closure-scoped cache in buildGrantRemintCallbacks bounds it to <=1 fetch
  // while each call still returns the rootNodeId-filtered subset.
  it('Test 1b: listSentGrants is fetched at most once across multiple queryGrantsFn calls, filtering stays correct per node', async () => {
    const transport = makeTransport([
      {
        shareId: SHARE_ID_SURVIVING,
        recipientPublicKey: RECIPIENT_PUB_KEY_A,
        isRevoked: false,
        rootNodeId: ROOT_NODE_ID,
      },
      {
        shareId: SHARE_ID_OTHER_ROOT,
        recipientPublicKey: RECIPIENT_PUB_KEY_B,
        isRevoked: false,
        rootNodeId: OTHER_NODE_ID,
      },
    ]);
    const callbacks = buildGrantRemintCallbacks(transport);

    // Invoke across multiple nodes within one pass.
    const rootGrants = await callbacks.queryGrantsFn(ROOT_NODE_ID);
    const otherGrants = await callbacks.queryGrantsFn(OTHER_NODE_ID);
    const rootGrantsAgain = await callbacks.queryGrantsFn(ROOT_NODE_ID);

    // Single fetch across all three calls (the memo).
    expect(transport.listSentGrants).toHaveBeenCalledTimes(1);

    // Per-node rootNodeId filtering is unchanged.
    expect(rootGrants).toEqual([
      { shareId: SHARE_ID_SURVIVING, recipientPublicKey: RECIPIENT_PUB_KEY_A, isRevoked: false },
    ]);
    expect(otherGrants).toEqual([
      { shareId: SHARE_ID_OTHER_ROOT, recipientPublicKey: RECIPIENT_PUB_KEY_B, isRevoked: false },
    ]);
    expect(rootGrantsAgain).toEqual(rootGrants);
  });

  it('Test 1c: the cache is scoped per buildGrantRemintCallbacks call — a fresh callbacks bundle re-fetches (no global/static cache)', async () => {
    const grants: GrantRow[] = [
      {
        shareId: SHARE_ID_SURVIVING,
        recipientPublicKey: RECIPIENT_PUB_KEY_A,
        isRevoked: false,
        rootNodeId: ROOT_NODE_ID,
      },
    ];
    const transport = makeTransport(grants);

    const callbacksA = buildGrantRemintCallbacks(transport);
    await callbacksA.queryGrantsFn(ROOT_NODE_ID);
    await callbacksA.queryGrantsFn(ROOT_NODE_ID);
    expect(transport.listSentGrants).toHaveBeenCalledTimes(1);

    // A new reconcile pass (new callbacks bundle) must fetch again — proving the
    // memo is closure-scoped, not module-global.
    const callbacksB = buildGrantRemintCallbacks(transport);
    await callbacksB.queryGrantsFn(ROOT_NODE_ID);
    expect(transport.listSentGrants).toHaveBeenCalledTimes(2);
  });
});

describe('runOwnerReconcile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.wrapKey.mockResolvedValue(MOCK_WRAPPED_BYTES);
  });

  it('Test 2: revoked grant -> transport.deleteGrant called, transport.updateGrant NOT called', async () => {
    const transport = makeTransport([
      {
        shareId: SHARE_ID_REVOKED,
        recipientPublicKey: RECIPIENT_PUB_KEY_B,
        isRevoked: true,
        rootNodeId: ROOT_NODE_ID,
      },
    ]);
    const ctx = makeCtx();
    const job = makeJobRecord();

    await runOwnerReconcile(ROOT_NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, transport);

    expect(transport.deleteGrant).toHaveBeenCalledWith(SHARE_ID_REVOKED);
    expect(transport.deleteGrant).toHaveBeenCalledTimes(1);
    expect(transport.updateGrant).not.toHaveBeenCalled();
  });

  it('Test 3: surviving grant -> transport.updateGrant called with new encrypted key + generation, transport.deleteGrant NOT called', async () => {
    const transport = makeTransport([
      {
        shareId: SHARE_ID_SURVIVING,
        recipientPublicKey: RECIPIENT_PUB_KEY_A,
        isRevoked: false,
        rootNodeId: ROOT_NODE_ID,
      },
    ]);
    const ctx = makeCtx();
    const job = makeJobRecord();

    await runOwnerReconcile(ROOT_NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, transport);

    expect(transport.updateGrant).toHaveBeenCalledWith(
      SHARE_ID_SURVIVING,
      EXPECTED_ENCRYPTED_KEY,
      NEW_GENERATION
    );
    expect(transport.updateGrant).toHaveBeenCalledTimes(1);
    expect(transport.deleteGrant).not.toHaveBeenCalled();
  });

  it('Test 4: non-matching rootNodeId grants are dropped by the filter and never reach the transport update/delete calls', async () => {
    const transport = makeTransport([
      {
        shareId: SHARE_ID_OTHER_ROOT,
        recipientPublicKey: RECIPIENT_PUB_KEY_B,
        isRevoked: false,
        rootNodeId: OTHER_NODE_ID,
      },
    ]);
    const ctx = makeCtx();
    const job = makeJobRecord();

    await runOwnerReconcile(ROOT_NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, transport);

    expect(transport.updateGrant).not.toHaveBeenCalled();
    expect(transport.deleteGrant).not.toHaveBeenCalled();
  });

  // D-03d consumer 2 (T-80-18): the recipientPublicKey round-trips through the
  // untrusted relay via listSentGrants. When the node's owner-sealed pin list
  // (getRecipientPubkeyPins read path) does NOT include that recipient, the
  // reconcile pass MUST fail closed — throw and never wrap/persist the read key.
  it('Test 5 (D-03d mismatch): reconcile fails closed when the pin list omits the surviving grant recipient', async () => {
    const transport = makeTransport(
      [
        {
          shareId: SHARE_ID_SURVIVING,
          recipientPublicKey: RECIPIENT_PUB_KEY_A,
          isRevoked: false,
          rootNodeId: ROOT_NODE_ID,
        },
      ],
      // Pin list contains a DIFFERENT recipient — relay substituted the pubkey.
      [RECIPIENT_PUB_KEY_B]
    );
    const ctx = makeCtx();
    const job = makeJobRecord();

    await expect(
      runOwnerReconcile(ROOT_NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, transport)
    ).rejects.toThrow(/pinned/i);

    // Fail-closed: no wrap, no persistence of the re-minted key.
    expect(mockFns.wrapKey).not.toHaveBeenCalled();
    expect(transport.updateGrant).not.toHaveBeenCalled();
  });

  // D-03e no-legacy: an empty/absent owner-sealed pin list is a HARD failure,
  // never a TOFU pass — the reconcile pass throws for a surviving grant.
  it('Test 6 (D-03e absent): reconcile fails closed when the pin list is empty', async () => {
    const transport = makeTransport(
      [
        {
          shareId: SHARE_ID_SURVIVING,
          recipientPublicKey: RECIPIENT_PUB_KEY_A,
          isRevoked: false,
          rootNodeId: ROOT_NODE_ID,
        },
      ],
      [] // absent/empty pin list
    );
    const ctx = makeCtx();
    const job = makeJobRecord();

    await expect(
      runOwnerReconcile(ROOT_NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, transport)
    ).rejects.toThrow();

    expect(mockFns.wrapKey).not.toHaveBeenCalled();
    expect(transport.updateGrant).not.toHaveBeenCalled();
  });

  it('Test 7 (pin source): getPinsFn resolves via getRecipientPubkeyPins, matching pin wraps as before', async () => {
    const transport = makeTransport([
      {
        shareId: SHARE_ID_SURVIVING,
        recipientPublicKey: RECIPIENT_PUB_KEY_A,
        isRevoked: false,
        rootNodeId: ROOT_NODE_ID,
      },
    ]);
    const ctx = makeCtx();
    const job = makeJobRecord();

    await runOwnerReconcile(ROOT_NODE_ID, NEW_READ_KEY, NEW_GENERATION, job, ctx, transport);

    // The pin source is the owner-sealed read path, resolved for the node.
    expect(transport.getRecipientPubkeyPins).toHaveBeenCalledWith(ROOT_NODE_ID);
    expect(transport.updateGrant).toHaveBeenCalledWith(
      SHARE_ID_SURVIVING,
      EXPECTED_ENCRYPTED_KEY,
      NEW_GENERATION
    );
  });
});
