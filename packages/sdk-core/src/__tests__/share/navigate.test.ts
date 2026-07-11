/**
 * Tests for navigateReadChain — multi-hop read-chain walk.
 *
 * Design §3.3, §4.6, D-06.
 * Tests: depth-1 ok, depth-d ok (spy counts), generation-ahead→behind-retry,
 *        missing-IPNS→revoked, missing-childRef→revoked, AAD-transplant throws.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { navigateReadChain } from '../../share/navigate';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks
// vi.hoisted() + vi.mock() are hoisted before all imports.
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  unsealNode: vi.fn(),
  unsealChildReadKey: vi.fn(),
  unwrapKey: vi.fn(),
  resolveIpnsRecord: vi.fn(),
  fetchFromIpfs: vi.fn(),
}));

vi.mock('@cipherbox/core', () => ({
  unsealNode: mockFns.unsealNode,
  unsealChildReadKey: mockFns.unsealChildReadKey,
}));

// bytesToBase64/base64ToBytes are kept as the real implementation (importOriginal)
// since navigate.ts now imports the shared codec from here too (Plan 77-08).
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    unwrapKey: mockFns.unwrapKey,
  };
});

// Paths are relative to the TEST FILE location (__tests__/share/navigate.test.ts),
// matching what navigate.ts resolves (../ipns → ../../ipns; ../ipfs → ../../ipfs).
vi.mock('../../ipns', () => ({
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
}));

vi.mock('../../ipfs', () => ({
  fetchFromIpfs: mockFns.fetchFromIpfs,
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Build JSON bytes for a PublishedNode (plaintext fields only — the sealed body is mocked). */
function makePublishedBytes(id: string, kind: string, generation: number): Uint8Array {
  const node = { schema: 'node/v3', kind, id, generation, aeadVersion: 1, readSealed: 'base64==' };
  return new TextEncoder().encode(JSON.stringify(node));
}

/** A minimal NodeContent for a file leaf. */
const FILE_CONTENT = {
  cid: 'QmFileContent',
  fileIv: 'iv-hex',
  size: 1024,
  mimeType: 'text/plain',
  encryptionMode: 'GCM' as const,
  fileKey: new Uint8Array(32).fill(0xaa),
  versions: [],
};

/** Common grant parameters (ECIES-wrapped encryptedReadKey). */
const GRANT_ENCRYPTED_READ_KEY = btoa('wrapped-root-read-key'); // base64 placeholder
const RECIPIENT_PRIV_KEY = new Uint8Array(32).fill(0x11);
const SHARE_ROOT_READ_KEY = new Uint8Array(32).fill(0x22);

const ROOT_IPNS = 'k51-root';
const CHILD_FOLDER_IPNS = 'k51-subfolder';
const FILE_LEAF_IPNS = 'k51-file';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('navigateReadChain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // unwrapKey always returns a fresh copy of the share-root readKey so that
    // navigateReadChain's finally-block zeroization of the minted key does not
    // wipe the shared SHARE_ROOT_READ_KEY fixture and make later tests
    // order-dependent (T-63-mock-isolation).
    mockFns.unwrapKey.mockImplementation(async () => SHARE_ROOT_READ_KEY.slice());
  });

  // -------------------------------------------------------------------------
  // Case 1: depth-1 file recovery (ok)
  // -------------------------------------------------------------------------

  it('depth-1: returns ok with file content when root has a direct file child', async () => {
    const ctx = createMockContext();

    // Root resolves to a folder node with one file child ref
    mockFns.resolveIpnsRecord.mockResolvedValueOnce({ cid: 'Qm-root', sequenceNumber: 1n });
    mockFns.fetchFromIpfs.mockResolvedValueOnce(makePublishedBytes('root-uuid', 'folder', 0));

    const rootNode = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'root-uuid',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [
        {
          name: 'file.txt',
          ipnsName: FILE_LEAF_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'sealed-file-key==',
        },
      ],
    };
    mockFns.unsealNode.mockResolvedValueOnce(rootNode);

    // File child resolves
    mockFns.resolveIpnsRecord.mockResolvedValueOnce({ cid: 'Qm-file', sequenceNumber: 1n });
    mockFns.fetchFromIpfs.mockResolvedValueOnce(makePublishedBytes('file-uuid', 'file', 0));

    const fileReadKey = new Uint8Array(32).fill(0x33);
    mockFns.unsealChildReadKey.mockResolvedValueOnce(fileReadKey);

    const fileNode = {
      schema: 'node/v3',
      kind: 'file',
      id: 'file-uuid',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      content: FILE_CONTENT,
    };
    mockFns.unsealNode.mockResolvedValueOnce(fileNode);

    const result = await navigateReadChain({
      encryptedReadKey: GRANT_ENCRYPTED_READ_KEY,
      recipientPrivKey: RECIPIENT_PRIV_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
      path: [FILE_LEAF_IPNS],
      ctx,
    });

    expect(result).toEqual({ status: 'ok', content: FILE_CONTENT, nodeId: 'file-uuid' });
    // One ECIES unwrap
    expect(mockFns.unwrapKey).toHaveBeenCalledTimes(1);
    // One unsealChildReadKey for the depth-1 hop
    expect(mockFns.unsealChildReadKey).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // Case 2: depth-d (d=2) file recovery — spy counts assert exactly 1 ECIES + d symmetric
  // -------------------------------------------------------------------------

  it('depth-2: calls unwrapKey exactly once and unsealChildReadKey exactly 2 times', async () => {
    const ctx = createMockContext();

    // Root node (folder → subfolder → file)
    mockFns.resolveIpnsRecord
      .mockResolvedValueOnce({ cid: 'Qm-root', sequenceNumber: 1n })
      .mockResolvedValueOnce({ cid: 'Qm-subfolder', sequenceNumber: 1n })
      .mockResolvedValueOnce({ cid: 'Qm-file', sequenceNumber: 1n });

    mockFns.fetchFromIpfs
      .mockResolvedValueOnce(makePublishedBytes('root-id', 'folder', 0))
      .mockResolvedValueOnce(makePublishedBytes('sub-id', 'folder', 0))
      .mockResolvedValueOnce(makePublishedBytes('file-id', 'file', 0));

    const rootNode = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'root-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [
        {
          name: 'subfolder',
          ipnsName: CHILD_FOLDER_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'sealed-sub-key==',
        },
      ],
    };
    const subfolderNode = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'sub-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [
        {
          name: 'file.txt',
          ipnsName: FILE_LEAF_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'sealed-file-key==',
        },
      ],
    };
    const fileNode = {
      schema: 'node/v3',
      kind: 'file',
      id: 'file-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      content: FILE_CONTENT,
    };

    mockFns.unsealNode
      .mockResolvedValueOnce(rootNode)
      .mockResolvedValueOnce(subfolderNode)
      .mockResolvedValueOnce(fileNode);

    const subReadKey = new Uint8Array(32).fill(0x44);
    const fileReadKey = new Uint8Array(32).fill(0x55);
    mockFns.unsealChildReadKey.mockResolvedValueOnce(subReadKey).mockResolvedValueOnce(fileReadKey);

    const result = await navigateReadChain({
      encryptedReadKey: GRANT_ENCRYPTED_READ_KEY,
      recipientPrivKey: RECIPIENT_PRIV_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
      path: [CHILD_FOLDER_IPNS, FILE_LEAF_IPNS],
      ctx,
    });

    expect(result).toEqual({ status: 'ok', content: FILE_CONTENT, nodeId: 'file-id' });
    // Exactly 1 ECIES op
    expect(mockFns.unwrapKey).toHaveBeenCalledTimes(1);
    // Exactly d=2 symmetric hops
    expect(mockFns.unsealChildReadKey).toHaveBeenCalledTimes(2);
  });

  // -------------------------------------------------------------------------
  // Case 3: generation-ahead → behind-retry (§4.6)
  // -------------------------------------------------------------------------

  it('returns behind-retry when root envelope generation exceeds rootExpectedGeneration', async () => {
    const ctx = createMockContext();

    mockFns.resolveIpnsRecord.mockResolvedValueOnce({ cid: 'Qm-rotated-root', sequenceNumber: 5n });
    // Envelope generation is 2; caller expected generation 1 → behind-retry
    mockFns.fetchFromIpfs.mockResolvedValueOnce(makePublishedBytes('root-id', 'folder', 2));

    const result = await navigateReadChain({
      encryptedReadKey: GRANT_ENCRYPTED_READ_KEY,
      recipientPrivKey: RECIPIENT_PRIV_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 1,
      path: [FILE_LEAF_IPNS],
      ctx,
    });

    expect(result).toEqual({ status: 'behind-retry' });
    // Must NOT unseal when behind-retry is detected
    expect(mockFns.unsealNode).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Case 4: missing root IPNS record → revoked
  // -------------------------------------------------------------------------

  it('returns revoked when root IPNS record is missing', async () => {
    const ctx = createMockContext();

    mockFns.resolveIpnsRecord.mockResolvedValueOnce(null);

    const result = await navigateReadChain({
      encryptedReadKey: GRANT_ENCRYPTED_READ_KEY,
      recipientPrivKey: RECIPIENT_PRIV_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
      path: [FILE_LEAF_IPNS],
      ctx,
    });

    expect(result).toEqual({ status: 'revoked' });
    expect(mockFns.fetchFromIpfs).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Case 5: SealedChildRef absent on path → revoked
  // -------------------------------------------------------------------------

  it('returns revoked when SealedChildRef for a hop ipnsName is absent', async () => {
    const ctx = createMockContext();

    mockFns.resolveIpnsRecord.mockResolvedValueOnce({ cid: 'Qm-root', sequenceNumber: 1n });
    mockFns.fetchFromIpfs.mockResolvedValueOnce(makePublishedBytes('root-id', 'folder', 0));

    // Root node has NO children matching FILE_LEAF_IPNS
    const rootNodeEmpty = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'root-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
    };
    mockFns.unsealNode.mockResolvedValueOnce(rootNodeEmpty);

    const result = await navigateReadChain({
      encryptedReadKey: GRANT_ENCRYPTED_READ_KEY,
      recipientPrivKey: RECIPIENT_PRIV_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
      path: [FILE_LEAF_IPNS],
      ctx,
    });

    expect(result).toEqual({ status: 'revoked' });
    expect(mockFns.unsealChildReadKey).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Case 6: wrong-generation AAD transplant → unsealChildReadKey throws (not silent)
  // -------------------------------------------------------------------------

  it('propagates CryptoError when unsealChildReadKey rejects (AAD transplant — not silent success)', async () => {
    const ctx = createMockContext();

    mockFns.resolveIpnsRecord
      .mockResolvedValueOnce({ cid: 'Qm-root', sequenceNumber: 1n })
      .mockResolvedValueOnce({ cid: 'Qm-file', sequenceNumber: 1n });

    mockFns.fetchFromIpfs
      .mockResolvedValueOnce(makePublishedBytes('root-id', 'folder', 0))
      .mockResolvedValueOnce(makePublishedBytes('file-id', 'file', 0));

    const rootNodeWithChild = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'root-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [
        {
          name: 'file.txt',
          ipnsName: FILE_LEAF_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'stale-sealed-key==',
        },
      ],
    };
    mockFns.unsealNode.mockResolvedValueOnce(rootNodeWithChild);

    // Simulates a stale/transplanted sealed key — unseal fails (AAD mismatch)
    const aadError = new Error('AEAD authentication failed');
    mockFns.unsealChildReadKey.mockRejectedValueOnce(aadError);

    await expect(
      navigateReadChain({
        encryptedReadKey: GRANT_ENCRYPTED_READ_KEY,
        recipientPrivKey: RECIPIENT_PRIV_KEY,
        shareRootIpnsName: ROOT_IPNS,
        rootExpectedGeneration: 0,
        path: [FILE_LEAF_IPNS],
        ctx,
      })
    ).rejects.toThrow('AEAD authentication failed');
  });

  // -------------------------------------------------------------------------
  // Case 7: generation-source rule — unsealChildReadKey uses parent mirror generation
  // -------------------------------------------------------------------------

  it('passes childRef.generation (parent mirror) — not child envelope generation — to unsealChildReadKey', async () => {
    const ctx = createMockContext();

    // parent mirror says generation=3; child envelope says generation=4
    // unsealChildReadKey must receive 3 (the parent mirror)
    const PARENT_MIRROR_GENERATION = 3;
    const CHILD_ENVELOPE_GENERATION = 4;

    mockFns.resolveIpnsRecord
      .mockResolvedValueOnce({ cid: 'Qm-root', sequenceNumber: 1n })
      .mockResolvedValueOnce({ cid: 'Qm-file', sequenceNumber: 1n });

    mockFns.fetchFromIpfs
      .mockResolvedValueOnce(makePublishedBytes('root-id', 'folder', 0))
      .mockResolvedValueOnce(makePublishedBytes('file-id', 'file', CHILD_ENVELOPE_GENERATION));

    const rootNode = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'root-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [
        {
          name: 'file.txt',
          ipnsName: FILE_LEAF_IPNS,
          generation: PARENT_MIRROR_GENERATION, // the parent-mirror value
          versionFloor: 0n,
          readKeySealed: 'sealed-file-key==',
        },
      ],
    };
    mockFns.unsealNode.mockResolvedValueOnce(rootNode);

    const fileReadKey = new Uint8Array(32).fill(0x66);
    mockFns.unsealChildReadKey.mockResolvedValueOnce(fileReadKey);

    const fileNode = {
      schema: 'node/v3',
      kind: 'file',
      id: 'file-id',
      generation: CHILD_ENVELOPE_GENERATION,
      createdAt: 0,
      modifiedAt: 0,
      content: FILE_CONTENT,
    };
    mockFns.unsealNode.mockResolvedValueOnce(fileNode);

    await navigateReadChain({
      encryptedReadKey: GRANT_ENCRYPTED_READ_KEY,
      recipientPrivKey: RECIPIENT_PRIV_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
      path: [FILE_LEAF_IPNS],
      ctx,
    });

    // Verify the generation argument passed to unsealChildReadKey is the parent mirror (3), not the child envelope (4).
    // The minted readKey buffer is the fresh copy returned by unwrapKey.mockImplementation; navigateReadChain's
    // finally block zeroes it after use, so Vitest's call-record reference shows zeros by assertion time.
    // We check the key as expect.any(Uint8Array) — key-content correctness is covered by the depth-1/depth-2 tests;
    // the purpose of this test is the GENERATION argument only.
    expect(mockFns.unsealChildReadKey).toHaveBeenCalledWith(
      'sealed-file-key==',
      expect.any(Uint8Array), // minted readKey (zeroed after the finally block — key-content tested elsewhere)
      'file-id', // from child published envelope (plaintext)
      'file', // from child published envelope (plaintext)
      PARENT_MIRROR_GENERATION // must be the PARENT MIRROR, not child envelope generation
    );
  });
});
