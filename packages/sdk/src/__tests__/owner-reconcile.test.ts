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

vi.mock('@cipherbox/crypto', () => ({
  wrapKey: mockFns.wrapKey,
  generateRandomBytes: vi.fn(),
  unwrapKey: vi.fn(),
  reWrapKey: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ROOT_NODE_ID = 'node-aaaa-1111-bbbb-cccccccccccc';
const OTHER_NODE_ID = 'node-ffff-9999-eeee-dddddddddddd';
const NEW_READ_KEY = new Uint8Array(32).fill(0xab);
const NEW_GENERATION = 3;

const MOCK_WRAPPED_BYTES = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const EXPECTED_ENCRYPTED_KEY = btoa(String.fromCharCode(0xde, 0xad, 0xbe, 0xef));

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

function makeTransport(grants: GrantRow[]): OwnerReconcileTransport & {
  listSentGrants: ReturnType<typeof vi.fn>;
  updateGrant: ReturnType<typeof vi.fn>;
  deleteGrant: ReturnType<typeof vi.fn>;
} {
  return {
    listSentGrants: vi.fn().mockResolvedValue(grants),
    updateGrant: vi.fn().mockResolvedValue(undefined),
    deleteGrant: vi.fn().mockResolvedValue(undefined),
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
});
