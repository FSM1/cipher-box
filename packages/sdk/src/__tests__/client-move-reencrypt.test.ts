/**
 * TDD test: moveItem must re-encrypt FileMetadata with the destination folder key.
 *
 * Root cause: FileMetadata is AES-256-GCM encrypted with the parent folder's key
 * at upload time. When a file is moved to a folder with a different key, the
 * FileMetadata IPNS record must be re-published encrypted with the destination
 * folder key — otherwise all decrypt operations (download, preview, edit) fail
 * with "Decryption failed" because they supply the destination folder key.
 *
 * This test is RED before the fix (moveItem does not call resolveFileMetadata /
 * updateFileMetadata) and GREEN after (moveItem re-encrypts on move).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FileMetadata } from '@cipherbox/core';

// ── crypto mock ────────────────────────────────────────────────────────────────
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0x55)),
  hexToBytes: vi.fn((hex: string) => new Uint8Array(hex.length / 2)),
}));

// ── sdk-core mock ──────────────────────────────────────────────────────────────
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    createSubfolder: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    renameInFolder: vi.fn(),
    deleteFromFolder: vi.fn(),
    moveItem: vi.fn(),
    addFilePointerToFolder: vi.fn(),
    uploadFile: vi.fn(),
    downloadAndDecrypt: vi.fn(),
    resolveFileMetadata: vi.fn(),
    updateFileMetadata: vi.fn(),
    batchPublishIpnsRecords: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
    addToIpfs: vi.fn(),
    fetchFromIpfs: vi.fn(),
    unpinFromIpfs: vi.fn(),
  };
});

// ── bin / share mocks (not under test, silence missing-module errors) ─────────
vi.mock('../bin', () => ({
  loadBin: vi.fn(),
  addToBin: vi.fn(),
  restoreFromBin: vi.fn(),
  permanentDeleteFromBin: vi.fn(),
  emptyBin: vi.fn(),
  purgeExpiredEntries: vi.fn(),
}));

vi.mock('../share', () => ({
  createShareKey: vi.fn(),
  revokeShare: vi.fn(),
  reWrapForRecipients: vi.fn().mockResolvedValue({ failedRecipients: [] }),
}));

import * as sdkCore from '@cipherbox/sdk-core';

// ── helpers ────────────────────────────────────────────────────────────────────

const SRC_IPNS = 'k51src';
const DEST_IPNS = 'k51dest';
const FILE_ID = 'file-uuid-1';
const FILE_META_IPNS = 'k51filemeta';
const IPNS_PRIV_KEY_ENC = 'deadbeef01';

const SRC_FOLDER_KEY = new Uint8Array(32).fill(0x11);
const DEST_FOLDER_KEY = new Uint8Array(32).fill(0x22);

/** Populate the client's folderTree with src and dest folders. */
function setupFolders(client: CipherBoxClient) {
  const now = Date.now();
  const filePointer = {
    type: 'file' as const,
    id: FILE_ID,
    name: 'hello.txt',
    fileMetaIpnsName: FILE_META_IPNS,
    ipnsPrivateKeyEncrypted: IPNS_PRIV_KEY_ENC,
    createdAt: now,
    modifiedAt: now,
  };

  client.getFolderTree().set(SRC_IPNS, {
    ipnsName: SRC_IPNS,
    folderKey: new Uint8Array(SRC_FOLDER_KEY),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0xaa),
      privateKey: new Uint8Array(64).fill(0xbb),
    },
    sequenceNumber: 1n,
    children: [filePointer],
    metadata: null,
    lastLoadedAt: now,
  });

  client.getFolderTree().set(DEST_IPNS, {
    ipnsName: DEST_IPNS,
    folderKey: new Uint8Array(DEST_FOLDER_KEY),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0xcc),
      privateKey: new Uint8Array(64).fill(0xdd),
    },
    sequenceNumber: 1n,
    children: [],
    metadata: null,
    lastLoadedAt: now,
  });
}

/** Minimal valid FileMetadata */
const mockFileMeta: FileMetadata = {
  version: 'v1',
  cid: 'bafyfile',
  fileKeyEncrypted: 'aabbcc',
  fileIv: '112233',
  size: 42,
  mimeType: 'text/plain',
  encryptionMode: 'GCM',
  createdAt: 1000,
  modifiedAt: 1000,
};

// ── tests ──────────────────────────────────────────────────────────────────────

describe('CipherBoxClient.moveItem — file metadata re-encryption', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
    setupFolders(client);

    // sdkCore.moveItem returns the shuffled children arrays
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSourceChildren: [],
      updatedDestChildren: [
        {
          type: 'file',
          id: FILE_ID,
          name: 'hello.txt',
          fileMetaIpnsName: FILE_META_IPNS,
          ipnsPrivateKeyEncrypted: IPNS_PRIV_KEY_ENC,
          createdAt: 0,
          modifiedAt: 0,
        },
      ],
      movedItem: {
        type: 'file',
        id: FILE_ID,
        name: 'hello.txt',
        fileMetaIpnsName: FILE_META_IPNS,
        ipnsPrivateKeyEncrypted: IPNS_PRIV_KEY_ENC,
        createdAt: 0,
        modifiedAt: 0,
      },
    });

    // resolveFileMetadata returns metadata encrypted with source key
    vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
      metadata: mockFileMeta,
      metadataCid: 'bafymeta1',
    });

    // updateFileMetadata simulates successful re-encryption publish
    vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
      ipnsName: FILE_META_IPNS,
      metadataCid: 'bafymeta2',
      newSequenceNumber: 2n,
      prunedCids: [],
    });

    // updateFolderMetadataAndPublish returns new sequence numbers for both folders
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
  });

  it('calls resolveFileMetadata with the SOURCE folder key to read existing file metadata', async () => {
    await client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID);

    expect(sdkCore.resolveFileMetadata).toHaveBeenCalled();
    const call = vi.mocked(sdkCore.resolveFileMetadata).mock.calls[0];
    // First arg: fileMetaIpnsName
    expect(call[0]).toBe(FILE_META_IPNS);
    // Second arg: folderKey must be the SOURCE folder's key (not dest)
    expect(call[1]).toEqual(SRC_FOLDER_KEY);
  });

  it('calls updateFileMetadata with the DESTINATION folder key to re-encrypt file metadata', async () => {
    await client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID);

    expect(sdkCore.updateFileMetadata).toHaveBeenCalled();
    const call = vi.mocked(sdkCore.updateFileMetadata).mock.calls[0];
    const params = call[0] as Parameters<typeof sdkCore.updateFileMetadata>[0];
    // folderKey must be the DESTINATION folder's key
    expect(params.folderKey).toEqual(DEST_FOLDER_KEY);
    // Must not create a new version (re-encryption is not a content change)
    expect(params.createVersion).toBe(false);
    // Must carry the same content unchanged
    expect(params.updates).toEqual({});
    // Must use the correct IPNS name
    expect(params.fileMetaIpnsName).toBe(FILE_META_IPNS);
  });

  it('does NOT re-encrypt file metadata when moving a folder (no FilePointer involved)', async () => {
    const now = Date.now();
    const folderChild = {
      type: 'folder' as const,
      id: 'subfolder-uuid',
      name: 'SubDir',
      ipnsName: 'k51subfolder',
      folderKeyEncrypted: 'encfkey',
      ipnsPrivateKeyEncrypted: 'encipns',
      createdAt: now,
      modifiedAt: now,
    };

    // Replace file with folder child in source
    const srcState = client.getFolderTree().get(SRC_IPNS)!;
    srcState.children = [folderChild];
    client.getFolderTree().set(SRC_IPNS, srcState);

    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSourceChildren: [],
      updatedDestChildren: [folderChild],
      movedItem: folderChild,
    });

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'subfolder-uuid');

    expect(sdkCore.resolveFileMetadata).not.toHaveBeenCalled();
    expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
  });
});
