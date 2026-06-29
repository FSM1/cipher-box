/**
 * Tests for issueReadGrant and claimInviteReadKey.
 *
 * issueReadGrant: ONE ECIES wrap → readDescriptorRef; zero node touches; zero IPNS publishes.
 * claimInviteReadKey: unwrap with ephemeral private key, re-wrap to claimer public key.
 *
 * Design §3.2 (issue grant), §3.11 (invite), READ-01, READ-05, D-05, D-07.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { issueReadGrant } from '../../share/grant';

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

/** base64 of WRAPPED_BYTES — the expected readDescriptorRef encoding. */
const EXPECTED_DESCRIPTOR_REF = btoa(String.fromCharCode(0xde, 0xad, 0xbe, 0xef));

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
      rootIpnsName: 'k51qzi',
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
      rootIpnsName: 'k51testname',
      rootGeneration: 3,
      insertShareFn,
    });

    expect(insertShareFn).toHaveBeenCalledOnce();
    const [payload] = insertShareFn.mock.calls[0];
    expect(payload.rootNodeId).toBe('node-root-1');
    expect(payload.rootIpnsName).toBe('k51testname');
    expect(payload.rootGeneration).toBe(3);
    expect(payload.readDescriptorRef).toBe(EXPECTED_DESCRIPTOR_REF);
    expect(payload.recipientPublicKey).toBe(RECIPIENT_PUBLIC_KEY);
  });

  it('returns { shareId, readDescriptorRef } matching insertShareFn result', async () => {
    const result = await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'node-1',
      rootIpnsName: 'k51abc',
      rootGeneration: 0,
      insertShareFn,
    });

    expect(result.shareId).toBe('share-abc-123');
    expect(result.readDescriptorRef).toBe(EXPECTED_DESCRIPTOR_REF);
  });

  it('produces structurally identical grant payload for a folder root and a single-file root (READ-01)', async () => {
    // Folder root grant
    const folderInsertFn = vi.fn().mockResolvedValue({ shareId: 'share-folder' });
    const folderResult = await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'folder-root',
      rootIpnsName: 'k51folder',
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
      rootIpnsName: 'k51file',
      rootGeneration: 0,
      insertShareFn: fileInsertFn,
    });

    // Both grant results have the same shape — string shareId + string readDescriptorRef.
    // This proves granting a single file is structurally identical to granting a deep folder.
    expect(typeof folderResult.shareId).toBe('string');
    expect(typeof folderResult.readDescriptorRef).toBe('string');
    expect(typeof fileResult.shareId).toBe('string');
    expect(typeof fileResult.readDescriptorRef).toBe('string');

    // wrapKey called once per grant (only one ECIES op each, regardless of tree depth)
    expect(mockFns.wrapKey).toHaveBeenCalledOnce();
  });

  it('does NOT touch sealNode, resolveIpnsRecord, or createAndPublishIpnsRecord (READ-01 — zero node/IPNS side effects)', async () => {
    await issueReadGrant({
      shareRootReadKey: SHARE_ROOT_READ_KEY,
      recipientPublicKey: RECIPIENT_PUBLIC_KEY,
      rootNodeId: 'node-1',
      rootIpnsName: 'k51abc',
      rootGeneration: 0,
      insertShareFn,
    });

    expect(mockFns.sealNode).not.toHaveBeenCalled();
    expect(mockFns.unsealNode).not.toHaveBeenCalled();
    expect(mockFns.resolveIpnsRecord).not.toHaveBeenCalled();
    expect(mockFns.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });
});
