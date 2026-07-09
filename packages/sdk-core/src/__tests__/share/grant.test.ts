/**
 * Tests for issueReadGrant, claimInviteReadKey, and claimInvite.
 *
 * issueReadGrant: ONE ECIES wrap → encryptedReadKey; zero node touches; zero IPNS publishes.
 * claimInviteReadKey: unwrap with ephemeral private key, re-wrap to claimer public key.
 * claimInvite: full service flow — fetch invite data → claimInviteReadKey → insertShareFn.
 *
 * Design §3.2 (issue grant), §3.11 (invite), READ-01, READ-05, D-05, D-06, D-07.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { issueReadGrant, claimInviteReadKey, claimInvite } from '../../share/grant';

// ---------------------------------------------------------------------------
// Module mocks — hoisted before all imports.
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  wrapKey: vi.fn(),
  reWrapKey: vi.fn(),
  // Codec + IPNS mocks — never called during grant issuance (READ-01).
  sealNode: vi.fn(),
  unsealNode: vi.fn(),
  resolveIpnsRecord: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
}));

vi.mock('@cipherbox/crypto', () => ({
  wrapKey: mockFns.wrapKey,
  reWrapKey: mockFns.reWrapKey,
}));

// These are mocked to prove issueReadGrant never touches the node codec or IPNS.
vi.mock('@cipherbox/core', () => ({
  sealNode: mockFns.sealNode,
  unsealNode: mockFns.unsealNode,
}));

vi.mock('../../ipns', () => ({
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Fake 32-byte share-root readKey (caller-owned — must NOT be zeroed by grantee). */
const SHARE_ROOT_READ_KEY = new Uint8Array(32).fill(0x42);

/** Fake 65-byte uncompressed secp256k1 recipient public key. */
const RECIPIENT_PUBLIC_KEY = new Uint8Array(65).fill(0x04);

/** Fake ECIES-wrapped key bytes returned by the mocked wrapKey. */
const WRAPPED_BYTES = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

/** base64 of WRAPPED_BYTES — the expected encryptedReadKey encoding. */
const EXPECTED_ENCRYPTED_READ_KEY = btoa(String.fromCharCode(0xde, 0xad, 0xbe, 0xef));

// ---------------------------------------------------------------------------
// issueReadGrant tests (Task 1 — READ-01 / §3.2)
// ---------------------------------------------------------------------------

describe('issueReadGrant', () => {
  const insertShareFn = vi.fn<
    [Parameters<Parameters<typeof issueReadGrant>[0]['insertShareFn']>[0]],
    Promise<{ shareId: string }>
  >();

  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.wrapKey.mockResolvedValue(WRAPPED_BYTES);
    insertShareFn.mockResolvedValue({ shareId: 'share-abc-123' });
  });

  it('calls wrapKey exactly once with shareRootReadKey and recipientPublicKey', async () => {
    await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'node-1',
      shareRootIpnsName: 'k51qzi',
      rootGeneration: 0,
      insertShareFn,
    });

    expect(mockFns.wrapKey).toHaveBeenCalledOnce();
    expect(mockFns.wrapKey).toHaveBeenCalledWith(SHARE_ROOT_READ_KEY, RECIPIENT_PUBLIC_KEY);
  });

  it('calls insertShareFn exactly once with the correct grant payload', async () => {
    await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'node-root-1',
      shareRootIpnsName: 'k51testname',
      rootGeneration: 3,
      insertShareFn,
    });

    expect(insertShareFn).toHaveBeenCalledOnce();
    const [payload] = insertShareFn.mock.calls[0];
    expect(payload.rootNodeId).toBe('node-root-1');
    expect(payload.shareRootIpnsName).toBe('k51testname');
    expect(payload.rootGeneration).toBe(3);
    expect(payload.encryptedReadKey).toBe(EXPECTED_ENCRYPTED_READ_KEY);
    expect(payload.recipientPublicKey).toBe(RECIPIENT_PUBLIC_KEY);
  });

  it('returns { shareId, encryptedReadKey } matching insertShareFn result', async () => {
    const result = await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'node-1',
      shareRootIpnsName: 'k51abc',
      rootGeneration: 0,
      insertShareFn,
    });

    expect(result.shareId).toBe('share-abc-123');
    expect(result.encryptedReadKey).toBe(EXPECTED_ENCRYPTED_READ_KEY);
  });

  it('produces structurally identical grant payload for a folder root and a single-file root (READ-01)', async () => {
    // Folder root grant
    const folderInsertFn = vi.fn().mockResolvedValue({ shareId: 'share-folder' });
    const folderResult = await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'folder-root',
      shareRootIpnsName: 'k51folder',
      rootGeneration: 0,
      insertShareFn: folderInsertFn,
    });

    vi.clearAllMocks();
    const WRAPPED2 = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);
    mockFns.wrapKey.mockResolvedValue(WRAPPED2);

    // Single-file root grant (structurally identical to folder grant)
    const fileInsertFn = vi.fn().mockResolvedValue({ shareId: 'share-file' });
    const fileResult = await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'file-root',
      shareRootIpnsName: 'k51file',
      rootGeneration: 0,
      insertShareFn: fileInsertFn,
    });

    // Both grant results have the same shape — string shareId + string encryptedReadKey.
    // This proves granting a single file is structurally identical to granting a deep folder.
    expect(typeof folderResult.shareId).toBe('string');
    expect(typeof folderResult.encryptedReadKey).toBe('string');
    expect(typeof fileResult.shareId).toBe('string');
    expect(typeof fileResult.encryptedReadKey).toBe('string');

    // wrapKey called once per grant (only one ECIES op each, regardless of tree depth)
    expect(mockFns.wrapKey).toHaveBeenCalledOnce();
  });

  it('does NOT touch sealNode, resolveIpnsRecord, or createAndPublishIpnsRecord (READ-01 — zero node/IPNS side effects)', async () => {
    await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'node-1',
      shareRootIpnsName: 'k51abc',
      rootGeneration: 0,
      insertShareFn,
    });

    expect(mockFns.sealNode).not.toHaveBeenCalled();
    expect(mockFns.unsealNode).not.toHaveBeenCalled();
    expect(mockFns.resolveIpnsRecord).not.toHaveBeenCalled();
    expect(mockFns.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// claimInviteReadKey tests (Task 2 — READ-05 / D-07 / §3.11)
// ---------------------------------------------------------------------------

describe('claimInviteReadKey', () => {
  /** Fake 32-byte secp256k1 ephemeral private key (from URL fragment). */
  const EPHEMERAL_PRIV_KEY = new Uint8Array(32).fill(0x11);

  /** Fake 65-byte uncompressed secp256k1 claimer public key. */
  const CLAIMER_PUBLIC_KEY = new Uint8Array(65).fill(0x04);

  /** Fake invite-wrapped bytes (ECIES ciphertext encrypted to ephemeral pubkey). */
  const INVITE_WRAPPED_BYTES = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

  /** base64 of INVITE_WRAPPED_BYTES — the invite encryptedReadKey. */
  const INVITE_ENCRYPTED_READ_KEY = btoa(String.fromCharCode(0x01, 0x02, 0x03, 0x04));

  /** Fake re-wrapped bytes returned by the mocked reWrapKey. */
  const CLAIMER_WRAPPED_BYTES = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);

  /** base64 of CLAIMER_WRAPPED_BYTES — the expected claimer encryptedReadKey. */
  const EXPECTED_CLAIMER_REF = btoa(String.fromCharCode(0xca, 0xfe, 0xba, 0xbe));

  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.reWrapKey.mockResolvedValue(CLAIMER_WRAPPED_BYTES);
  });

  it('calls reWrapKey with the decoded invite bytes, ephemeralPrivateKey, and claimerPublicKey', async () => {
    await claimInviteReadKey({
      encryptedReadKey: INVITE_ENCRYPTED_READ_KEY,
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
    });

    expect(mockFns.reWrapKey).toHaveBeenCalledOnce();
    expect(mockFns.reWrapKey).toHaveBeenCalledWith(
      INVITE_WRAPPED_BYTES,
      EPHEMERAL_PRIV_KEY,
      CLAIMER_PUBLIC_KEY
    );
  });

  it('returns the base64-encoded result of reWrapKey (standard grant encryptedReadKey)', async () => {
    const result = await claimInviteReadKey({
      encryptedReadKey: INVITE_ENCRYPTED_READ_KEY,
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
    });

    expect(result).toBe(EXPECTED_CLAIMER_REF);
  });

  it('returns a plain string — no encryptedChildKeys fan-out (D-07)', async () => {
    const result = await claimInviteReadKey({
      encryptedReadKey: INVITE_ENCRYPTED_READ_KEY,
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
    });

    // A plain string return proves no encryptedChildKeys array is produced.
    expect(typeof result).toBe('string');
    // Narrow-proof: the result has no property that would exist on a fan-out structure.
    expect(result).not.toHaveProperty('encryptedChildKeys');
  });

  it('uses reWrapKey (not separate unwrapKey + wrapKey) — intermediate zeroization delegated to reWrapKey (T-63-05)', async () => {
    await claimInviteReadKey({
      encryptedReadKey: INVITE_ENCRYPTED_READ_KEY,
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
    });

    // reWrapKey zeros the intermediate share-root readKey in its own finally block.
    // Using reWrapKey (not manual unwrapKey + zero + wrapKey) satisfies T-63-05.
    expect(mockFns.reWrapKey).toHaveBeenCalledOnce();
    // wrapKey is NOT called separately — reWrapKey owns the entire unwrap+rewrap.
    expect(mockFns.wrapKey).not.toHaveBeenCalled();
  });

  it('does NOT touch sealNode, resolveIpnsRecord, or createAndPublishIpnsRecord (READ-05 — no node/IPNS side effects)', async () => {
    await claimInviteReadKey({
      encryptedReadKey: INVITE_ENCRYPTED_READ_KEY,
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
    });

    expect(mockFns.sealNode).not.toHaveBeenCalled();
    expect(mockFns.unsealNode).not.toHaveBeenCalled();
    expect(mockFns.resolveIpnsRecord).not.toHaveBeenCalled();
    expect(mockFns.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// claimInvite tests (Plan 65-03 — §3.11 / D-06)
// ---------------------------------------------------------------------------

describe('claimInvite', () => {
  /** Fake 32-byte secp256k1 ephemeral private key (from URL fragment). */
  const EPHEMERAL_PRIV_KEY = new Uint8Array(32).fill(0x11);

  /** Fake 65-byte uncompressed secp256k1 claimer public key. */
  const CLAIMER_PUBLIC_KEY = new Uint8Array(65).fill(0x04);

  /** Fake invite-wrapped bytes (ECIES ciphertext encrypted to ephemeral pubkey). */
  const INVITE_WRAPPED_BYTES = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

  /** base64 of INVITE_WRAPPED_BYTES — the invite encryptedReadKey in the invite row. */
  const INVITE_ENCRYPTED_READ_KEY = btoa(String.fromCharCode(0x01, 0x02, 0x03, 0x04));

  /** Fake re-wrapped bytes returned by the mocked reWrapKey. */
  const CLAIMER_WRAPPED_BYTES = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);

  /** base64 of CLAIMER_WRAPPED_BYTES — the expected claimer encryptedReadKey. */
  const EXPECTED_CLAIMER_REF = btoa(String.fromCharCode(0xca, 0xfe, 0xba, 0xbe));

  const getInviteDataFn = vi.fn<[], Promise<{ encryptedReadKey: string }>>();
  const insertShareFn = vi.fn<
    [Parameters<Parameters<typeof claimInvite>[0]['insertShareFn']>[0]],
    Promise<{ shareId: string }>
  >();

  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.reWrapKey.mockResolvedValue(CLAIMER_WRAPPED_BYTES);
    getInviteDataFn.mockResolvedValue({ encryptedReadKey: INVITE_ENCRYPTED_READ_KEY });
    insertShareFn.mockResolvedValue({ shareId: 'share-claim-001' });
  });

  it('calls getInviteDataFn exactly once with the inviteToken', async () => {
    await claimInvite({
      inviteToken: 'tok-abc',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
      rootNodeId: 'node-root-1',
      shareRootIpnsName: 'k51inviteroot',
      rootGeneration: 0,
      getInviteDataFn,
      insertShareFn,
    });

    expect(getInviteDataFn).toHaveBeenCalledOnce();
    expect(getInviteDataFn).toHaveBeenCalledWith('tok-abc');
  });

  it('calls reWrapKey exactly once with invite-wrapped bytes, ephemeralPrivateKey, claimerPublicKey', async () => {
    // claimInvite zeroes its owned ephemeral-key copy in a finally block, which means
    // mock.calls[] holds a reference to the now-zeroed buffer after the await resolves.
    // Capture the argument values at call time via mockImplementation to bypass this.
    let capturedArgs: [Uint8Array, Uint8Array, Uint8Array] | undefined;
    mockFns.reWrapKey.mockImplementation(
      async (wrapped: Uint8Array, ephKey: Uint8Array, clKey: Uint8Array) => {
        capturedArgs = [new Uint8Array(wrapped), new Uint8Array(ephKey), new Uint8Array(clKey)];
        return CLAIMER_WRAPPED_BYTES;
      }
    );

    await claimInvite({
      inviteToken: 'tok-abc',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
      rootNodeId: 'node-root-1',
      shareRootIpnsName: 'k51inviteroot',
      rootGeneration: 0,
      getInviteDataFn,
      insertShareFn,
    });

    expect(mockFns.reWrapKey).toHaveBeenCalledOnce();
    expect(capturedArgs![0]).toEqual(INVITE_WRAPPED_BYTES);
    expect(capturedArgs![1]).toEqual(EPHEMERAL_PRIV_KEY);
    expect(capturedArgs![2]).toEqual(CLAIMER_PUBLIC_KEY);
  });

  it('persists trimmed rootNodeId and shareRootIpnsName — not raw whitespace-padded input', async () => {
    await claimInvite({
      inviteToken: 'tok-abc',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
      rootNodeId: '  node-root-1  ',
      shareRootIpnsName: '  k51inviteroot  ',
      rootGeneration: 0,
      getInviteDataFn,
      insertShareFn,
    });

    const [payload] = insertShareFn.mock.calls[0];
    expect(payload.rootNodeId).toBe('node-root-1');
    expect(payload.shareRootIpnsName).toBe('k51inviteroot');
  });

  it('snapshots key buffers before getInviteDataFn so a mid-await caller zeroing cannot corrupt the re-wrap', async () => {
    const mutableEphemeralKey = new Uint8Array(32).fill(0x11);
    const mutableClaimerKey = new Uint8Array(65).fill(0x04);

    let capturedEphemeral: Uint8Array | undefined;
    let capturedClaimer: Uint8Array | undefined;
    mockFns.reWrapKey.mockImplementation(
      async (wrapped: Uint8Array, ephKey: Uint8Array, clKey: Uint8Array) => {
        capturedEphemeral = new Uint8Array(ephKey);
        capturedClaimer = new Uint8Array(clKey);
        return CLAIMER_WRAPPED_BYTES;
      }
    );

    // Simulate caller zeroing both input buffers while getInviteDataFn is in-flight
    const zeroingGetFn = vi.fn().mockImplementation(async () => {
      mutableEphemeralKey.fill(0);
      mutableClaimerKey.fill(0);
      return { encryptedReadKey: INVITE_ENCRYPTED_READ_KEY };
    });

    await claimInvite({
      inviteToken: 'tok-abc',
      ephemeralPrivateKey: mutableEphemeralKey,
      claimerPublicKey: mutableClaimerKey,
      rootNodeId: 'node-root-1',
      shareRootIpnsName: 'k51inviteroot',
      rootGeneration: 0,
      getInviteDataFn: zeroingGetFn,
      insertShareFn,
    });

    // Snapshotted copies preserve the original bytes despite the caller zeroing them mid-await
    expect(capturedEphemeral).toEqual(new Uint8Array(32).fill(0x11));
    expect(capturedClaimer).toEqual(new Uint8Array(65).fill(0x04));
  });

  it('calls insertShareFn exactly once per claim with correct standard grant payload — no encryptedChildKeys (D-06)', async () => {
    await claimInvite({
      inviteToken: 'tok-abc',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
      rootNodeId: 'node-root-1',
      shareRootIpnsName: 'k51inviteroot',
      rootGeneration: 2,
      getInviteDataFn,
      insertShareFn,
    });

    expect(insertShareFn).toHaveBeenCalledOnce();
    const [payload] = insertShareFn.mock.calls[0];
    // claimInvite passes a snapshotted copy of claimerPublicKey — use toStrictEqual, not toBe.
    expect(payload.recipientPublicKey).toStrictEqual(CLAIMER_PUBLIC_KEY);
    expect(payload.rootNodeId).toBe('node-root-1');
    expect(payload.shareRootIpnsName).toBe('k51inviteroot');
    expect(payload.rootGeneration).toBe(2);
    expect(payload.encryptedReadKey).toBe(EXPECTED_CLAIMER_REF);
    // No encryptedChildKeys fan-out — Success Criterion 4 / D-06
    expect(payload).not.toHaveProperty('encryptedChildKeys');
  });

  it('returns { shareId, encryptedReadKey } matching insertShareFn and the re-wrapped key', async () => {
    const result = await claimInvite({
      inviteToken: 'tok-xyz',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
      rootNodeId: 'node-root-1',
      shareRootIpnsName: 'k51inviteroot',
      rootGeneration: 0,
      getInviteDataFn,
      insertShareFn,
    });

    expect(result.shareId).toBe('share-claim-001');
    expect(result.encryptedReadKey).toBe(EXPECTED_CLAIMER_REF);
  });

  it('two claims of the same invite produce two independent standard grants of the same readKey (D-06 multi-claim)', async () => {
    const claimerPubKey1 = new Uint8Array(65).fill(0x04);
    const claimerPubKey2 = new Uint8Array(65).fill(0x05);

    const insertShareFn1 = vi.fn().mockResolvedValue({ shareId: 'share-claimer-1' });
    const insertShareFn2 = vi.fn().mockResolvedValue({ shareId: 'share-claimer-2' });

    const claimerWrapped1 = new Uint8Array([0x11, 0x22]);
    const claimerWrapped2 = new Uint8Array([0x33, 0x44]);

    // First claim
    mockFns.reWrapKey.mockResolvedValueOnce(claimerWrapped1);
    const result1 = await claimInvite({
      inviteToken: 'tok-shared',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: claimerPubKey1,
      rootNodeId: 'node-root-shared',
      shareRootIpnsName: 'k51shared',
      rootGeneration: 1,
      getInviteDataFn,
      insertShareFn: insertShareFn1,
    });

    // Second claim
    mockFns.reWrapKey.mockResolvedValueOnce(claimerWrapped2);
    const result2 = await claimInvite({
      inviteToken: 'tok-shared',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: claimerPubKey2,
      rootNodeId: 'node-root-shared',
      shareRootIpnsName: 'k51shared',
      rootGeneration: 1,
      getInviteDataFn,
      insertShareFn: insertShareFn2,
    });

    // Each claim calls getInviteDataFn exactly once (total 2 calls)
    expect(getInviteDataFn).toHaveBeenCalledTimes(2);
    // Each insertShareFn called exactly once with its own claimer
    expect(insertShareFn1).toHaveBeenCalledOnce();
    expect(insertShareFn2).toHaveBeenCalledOnce();
    // Each claim yields a different shareId — independent grants
    expect(result1.shareId).toBe('share-claimer-1');
    expect(result2.shareId).toBe('share-claimer-2');
    // Each payload has no encryptedChildKeys
    expect(insertShareFn1.mock.calls[0][0]).not.toHaveProperty('encryptedChildKeys');
    expect(insertShareFn2.mock.calls[0][0]).not.toHaveProperty('encryptedChildKeys');
  });

  it('does NOT touch sealNode, resolveIpnsRecord, or createAndPublishIpnsRecord (no node/IPNS side effects)', async () => {
    await claimInvite({
      inviteToken: 'tok-abc',
      ephemeralPrivateKey: EPHEMERAL_PRIV_KEY,
      claimerPublicKey: CLAIMER_PUBLIC_KEY,
      rootNodeId: 'node-root-1',
      shareRootIpnsName: 'k51inviteroot',
      rootGeneration: 0,
      getInviteDataFn,
      insertShareFn,
    });

    expect(mockFns.sealNode).not.toHaveBeenCalled();
    expect(mockFns.unsealNode).not.toHaveBeenCalled();
    expect(mockFns.resolveIpnsRecord).not.toHaveBeenCalled();
    expect(mockFns.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });
});
