import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import type { FolderChild, FilePointer } from '@cipherbox/core';

// ---- Mocks ----

vi.mock('@cipherbox/crypto', () => ({
  encryptAesGcm: vi.fn().mockResolvedValue(new Uint8Array([0xde, 0xad])),
  generateFileKey: vi.fn().mockReturnValue(new Uint8Array(32).fill(0x11)),
  generateIv: vi.fn().mockReturnValue(new Uint8Array(12).fill(0x22)),
  wrapKey: vi.fn().mockResolvedValue(new Uint8Array([0xaa, 0xbb, 0xcc])),
  bytesToHex: vi.fn().mockReturnValue('aabbcc'),
  hexToBytes: vi.fn().mockReturnValue(new Uint8Array(33).fill(9)),
  generateRandomBytes: vi.fn().mockReturnValue(new Uint8Array(32).fill(0x33)),
  generateEd25519Keypair: vi.fn().mockResolvedValue({
    publicKey: new Uint8Array(32).fill(0x44),
    privateKey: new Uint8Array(64).fill(0x55),
  }),
  deriveIpnsName: vi.fn().mockResolvedValue('k51subfolder'),
}));

vi.mock('@cipherbox/core', async () => {
  const actual = await vi.importActual<typeof import('@cipherbox/core')>('@cipherbox/core');
  return {
    ...actual,
    generateFileIpnsKeypair: vi.fn().mockResolvedValue({
      ipnsName: 'k51fileipns',
      publicKey: new Uint8Array(32).fill(0x66),
      privateKey: new Uint8Array(64).fill(0x77),
    }),
    encryptFolderMetadata: vi.fn().mockResolvedValue({ iv: 'mock-iv', data: 'mock-data' }),
    encryptFileMetadata: vi.fn().mockResolvedValue({ iv: 'mock-iv', data: 'mock-data' }),
    createIpnsRecord: vi.fn().mockResolvedValue({ value: new Uint8Array([1, 2, 3]) }),
    marshalIpnsRecord: vi.fn().mockReturnValue(new Uint8Array([4, 5, 6])),
  };
});

vi.mock('@cipherbox/sdk-core', () => ({
  updateFolderMetadataAndPublish: vi.fn().mockResolvedValue({
    cid: 'QmUpdated',
    newSequenceNumber: 2n,
  }),
  addToIpfs: vi.fn().mockResolvedValue({ cid: 'QmUploaded', size: 100, recorded: true }),
  batchPublishIpnsRecords: vi.fn().mockResolvedValue({ totalSucceeded: 1, totalFailed: 0 }),
  createAndPublishIpnsRecord: vi.fn().mockResolvedValue({ success: true, sequenceNumber: 1n }),
  resolveFileMetadata: vi.fn().mockResolvedValue({
    metadata: {
      version: 'v1',
      cid: 'QmOldFile',
      fileKeyEncrypted: 'oldkey',
      fileIv: 'oldiv',
      size: 50,
      mimeType: 'text/plain',
      encryptionMode: 'GCM',
      createdAt: 1000,
      modifiedAt: 1000,
    },
    metadataCid: 'QmOldMeta',
  }),
  updateFileMetadata: vi.fn().mockResolvedValue({
    ipnsRecord: {
      ipnsName: 'k51fileipns',
      recordBase64: 'mockbase64',
      metadataCid: 'QmNewMeta',
    },
    prunedCids: [],
  }),
}));

// ---- Imports under test (after mocks) ----

import {
  uploadToSharedFolder,
  createSharedSubfolder,
  renameInSharedFolder,
  deleteFromSharedFolder,
  updateSharedFile,
  updateSharePermission,
  type SharedWriteContext,
} from '../share/shared-write';

import {
  updateFolderMetadataAndPublish,
  addToIpfs,
  batchPublishIpnsRecords,
  createAndPublishIpnsRecord,
} from '@cipherbox/sdk-core';
import { wrapKey, encryptAesGcm } from '@cipherbox/crypto';

// ---- Helpers ----

function makeSWCtx(overrides?: Partial<SharedWriteContext>): SharedWriteContext {
  return {
    ctx: {
      apiUrl: 'http://localhost:3000',
      getAccessToken: async () => 'token',
    },
    folderKey: new Uint8Array(32).fill(1),
    ipnsPrivateKey: new Uint8Array(64).fill(2),
    ipnsName: 'k51folder',
    sequenceNumber: 1n,
    children: [],
    ownerPublicKey: new Uint8Array(33).fill(3),
    recipientPublicKey: new Uint8Array(33).fill(4),
    shareId: 'share-123',
    addShareKeysFn: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ---- Tests ----

describe('shared-write operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ---------- uploadToSharedFolder ----------

  describe('uploadToSharedFolder', () => {
    it('encrypts file, uploads to IPFS, creates file metadata IPNS, updates folder, and calls addShareKeysFn', async () => {
      const swCtx = makeSWCtx();
      const result = await uploadToSharedFolder(swCtx, {
        data: new Uint8Array([1, 2, 3]),
        fileName: 'test.txt',
        mimeType: 'text/plain',
      });

      // Encryption was called
      expect(encryptAesGcm).toHaveBeenCalled();

      // Uploaded encrypted content to IPFS
      expect(addToIpfs).toHaveBeenCalled();

      // File IPNS published via batch
      expect(batchPublishIpnsRecords).toHaveBeenCalled();

      // Parent folder updated
      expect(updateFolderMetadataAndPublish).toHaveBeenCalled();

      // Result contains FilePointer and updated state
      expect(result.filePointer).toBeDefined();
      expect(result.filePointer.type).toBe('file');
      expect(result.filePointer.name).toBe('test.txt');
      expect(result.updatedChildren).toHaveLength(1);
      expect(result.newSequenceNumber).toBe(2n);
    });

    it('wraps keys with both owner and recipient public keys', async () => {
      const swCtx = makeSWCtx();
      await uploadToSharedFolder(swCtx, {
        data: new Uint8Array([1]),
        fileName: 'test.txt',
      });

      // wrapKey is called multiple times: fileKey for owner, IPNS key for owner,
      // IPNS key for recipient, fileKey for recipient
      expect(wrapKey).toHaveBeenCalledTimes(4);
    });

    it('calls addShareKeysFn with file and file-ipns keys', async () => {
      const addFn = vi.fn().mockResolvedValue(undefined);
      const swCtx = makeSWCtx({ addShareKeysFn: addFn });

      await uploadToSharedFolder(swCtx, {
        data: new Uint8Array([1]),
        fileName: 'test.txt',
      });

      expect(addFn).toHaveBeenCalledWith(
        'share-123',
        expect.arrayContaining([
          expect.objectContaining({ keyType: 'file' }),
          expect.objectContaining({ keyType: 'file-ipns' }),
        ])
      );
    });

    it('warns but does not throw when addShareKeysFn fails', async () => {
      const addFn = vi.fn().mockRejectedValue(new Error('API error'));
      const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const swCtx = makeSWCtx({ addShareKeysFn: addFn });

      // Should not throw
      const result = await uploadToSharedFolder(swCtx, {
        data: new Uint8Array([1]),
        fileName: 'test.txt',
      });

      expect(result.filePointer).toBeDefined();
      expect(consoleWarn).toHaveBeenCalled();
      consoleWarn.mockRestore();
    });
  });

  // ---------- createSharedSubfolder ----------

  describe('createSharedSubfolder', () => {
    it('creates subfolder IPNS, updates parent, and calls addShareKeysFn', async () => {
      const swCtx = makeSWCtx();
      const result = await createSharedSubfolder(swCtx, { name: 'New Folder' });

      // Subfolder IPNS published
      expect(createAndPublishIpnsRecord).toHaveBeenCalled();

      // Parent folder updated
      expect(updateFolderMetadataAndPublish).toHaveBeenCalled();

      // Result contains FolderEntry
      expect(result.folderEntry).toBeDefined();
      expect(result.folderEntry.type).toBe('folder');
      expect(result.folderEntry.name).toBe('New Folder');
      expect(result.updatedChildren).toHaveLength(1);
      expect(result.newSequenceNumber).toBe(2n);
    });

    it('calls addShareKeysFn with folder and folder-ipns keys', async () => {
      const addFn = vi.fn().mockResolvedValue(undefined);
      const swCtx = makeSWCtx({ addShareKeysFn: addFn });

      await createSharedSubfolder(swCtx, { name: 'Sub' });

      expect(addFn).toHaveBeenCalledWith(
        'share-123',
        expect.arrayContaining([
          expect.objectContaining({ keyType: 'folder' }),
          expect.objectContaining({ keyType: 'folder-ipns' }),
        ])
      );
    });

    it('warns but does not throw when addShareKeysFn fails', async () => {
      const addFn = vi.fn().mockRejectedValue(new Error('API error'));
      const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const swCtx = makeSWCtx({ addShareKeysFn: addFn });

      const result = await createSharedSubfolder(swCtx, { name: 'Sub' });

      expect(result.folderEntry).toBeDefined();
      expect(consoleWarn).toHaveBeenCalled();
      consoleWarn.mockRestore();
    });
  });

  // ---------- renameInSharedFolder ----------

  describe('renameInSharedFolder', () => {
    it('updates the item name and republishes folder', async () => {
      const existingChild: FilePointer = {
        type: 'file',
        id: 'f1',
        name: 'old.txt',
        fileMetaIpnsName: 'k51file',
        ipnsPrivateKeyEncrypted: 'enc',
        createdAt: 1000,
        modifiedAt: 1000,
      };
      const swCtx = makeSWCtx({ children: [existingChild] });

      const result = await renameInSharedFolder(swCtx, {
        itemId: 'f1',
        newName: 'new.txt',
      });

      // Folder was re-published
      expect(updateFolderMetadataAndPublish).toHaveBeenCalled();

      // Updated children have new name
      const call = (updateFolderMetadataAndPublish as Mock).mock.calls[0][0];
      const updated = call.children.find((c: FolderChild) => c.id === 'f1');
      expect(updated.name).toBe('new.txt');
      expect(updated.modifiedAt).toBeGreaterThan(1000);

      expect(result.updatedChildren).toHaveLength(1);
      expect(result.newSequenceNumber).toBe(2n);
    });
  });

  // ---------- deleteFromSharedFolder ----------

  describe('deleteFromSharedFolder', () => {
    it('removes the item from children and republishes folder', async () => {
      const existingChild: FilePointer = {
        type: 'file',
        id: 'f1',
        name: 'doomed.txt',
        fileMetaIpnsName: 'k51file',
        ipnsPrivateKeyEncrypted: 'enc',
        createdAt: 1000,
        modifiedAt: 1000,
      };
      const swCtx = makeSWCtx({ children: [existingChild] });

      const result = await deleteFromSharedFolder(swCtx, { itemId: 'f1' });

      // Folder was re-published with empty children
      expect(updateFolderMetadataAndPublish).toHaveBeenCalled();
      const call = (updateFolderMetadataAndPublish as Mock).mock.calls[0][0];
      expect(call.children).toHaveLength(0);

      expect(result.updatedChildren).toHaveLength(0);
      expect(result.newSequenceNumber).toBe(2n);
    });
  });

  // ---------- updateSharedFile ----------

  describe('updateSharedFile', () => {
    it('encrypts new content, updates file metadata IPNS, and publishes', async () => {
      const getFileIpnsKeyFn = vi.fn().mockResolvedValue(new Uint8Array(64).fill(0x88));
      const addFn = vi.fn().mockResolvedValue(undefined);

      await updateSharedFile({
        ctx: {
          apiUrl: 'http://localhost:3000',
          getAccessToken: async () => 'token',
        },
        folderKey: new Uint8Array(32).fill(1),
        ownerPublicKey: new Uint8Array(33).fill(3),
        recipientPublicKey: new Uint8Array(33).fill(4),
        shareId: 'share-123',
        addShareKeysFn: addFn,
        filePointer: {
          type: 'file',
          id: 'f1',
          name: 'test.txt',
          fileMetaIpnsName: 'k51fileipns',
          ipnsPrivateKeyEncrypted: 'enc',
          createdAt: 1000,
          modifiedAt: 1000,
        },
        newContent: new Uint8Array([10, 20, 30]),
        getFileIpnsKeyFn,
      });

      // Content encrypted
      expect(encryptAesGcm).toHaveBeenCalled();

      // Uploaded to IPFS
      expect(addToIpfs).toHaveBeenCalled();

      // File metadata updated and published
      const { updateFileMetadata } = await import('@cipherbox/sdk-core');
      expect(updateFileMetadata).toHaveBeenCalled();
      expect(batchPublishIpnsRecords).toHaveBeenCalled();
    });

    it('calls addShareKeysFn with updated file key', async () => {
      const getFileIpnsKeyFn = vi.fn().mockResolvedValue(new Uint8Array(64).fill(0x88));
      const addFn = vi.fn().mockResolvedValue(undefined);

      await updateSharedFile({
        ctx: {
          apiUrl: 'http://localhost:3000',
          getAccessToken: async () => 'token',
        },
        folderKey: new Uint8Array(32).fill(1),
        ownerPublicKey: new Uint8Array(33).fill(3),
        recipientPublicKey: new Uint8Array(33).fill(4),
        shareId: 'share-123',
        addShareKeysFn: addFn,
        filePointer: {
          type: 'file',
          id: 'f1',
          name: 'test.txt',
          fileMetaIpnsName: 'k51fileipns',
          ipnsPrivateKeyEncrypted: 'enc',
          createdAt: 1000,
          modifiedAt: 1000,
        },
        newContent: new Uint8Array([10]),
        getFileIpnsKeyFn,
      });

      expect(addFn).toHaveBeenCalledWith('share-123', [
        expect.objectContaining({ keyType: 'file', itemId: 'f1' }),
      ]);
    });

    it('throws when getFileIpnsKeyFn returns null', async () => {
      const getFileIpnsKeyFn = vi.fn().mockResolvedValue(null);

      await expect(
        updateSharedFile({
          ctx: {
            apiUrl: 'http://localhost:3000',
            getAccessToken: async () => 'token',
          },
          folderKey: new Uint8Array(32).fill(1),
          ownerPublicKey: new Uint8Array(33).fill(3),
          recipientPublicKey: new Uint8Array(33).fill(4),
          shareId: 'share-123',
          addShareKeysFn: vi.fn(),
          filePointer: {
            type: 'file',
            id: 'f1',
            name: 'test.txt',
            fileMetaIpnsName: 'k51fileipns',
            ipnsPrivateKeyEncrypted: 'enc',
            createdAt: 1000,
            modifiedAt: 1000,
          },
          newContent: new Uint8Array([10]),
          getFileIpnsKeyFn,
        })
      ).rejects.toThrow(/IPNS key/i);
    });
  });

  // ---------- updateSharePermission ----------

  describe('updateSharePermission', () => {
    it('calls the provided updatePermissionFn with correct params', async () => {
      const updateFn = vi.fn().mockResolvedValue(undefined);

      await updateSharePermission({
        shareId: 'share-456',
        permission: 'write',
        encryptedIpnsKey: 'wrapped-key',
        updatePermissionFn: updateFn,
      });

      expect(updateFn).toHaveBeenCalledWith('share-456', {
        permission: 'write',
        encryptedIpnsKey: 'wrapped-key',
      });
    });

    it('calls without encryptedIpnsKey when not provided', async () => {
      const updateFn = vi.fn().mockResolvedValue(undefined);

      await updateSharePermission({
        shareId: 'share-456',
        permission: 'read',
        updatePermissionFn: updateFn,
      });

      expect(updateFn).toHaveBeenCalledWith('share-456', {
        permission: 'read',
        encryptedIpnsKey: undefined,
      });
    });
  });
});
