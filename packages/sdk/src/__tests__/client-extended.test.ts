/**
 * Extended client unit tests — covers bin, share, move, rename, upload,
 * download, and state management methods not covered in client.test.ts.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient, BinNotLoadedError } from '../client';
import type { SdkEvent } from '../events';
import { createTestConfig, setupFolder } from './helpers';

// Mock crypto (clearBytes used in uploadFile for key cleanup)
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
}));

// Mock sdk-core
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
    batchPublishIpnsRecords: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
    addToIpfs: vi.fn(),
    fetchFromIpfs: vi.fn(),
    unpinFromIpfs: vi.fn(),
  };
});

// Mock bin module
vi.mock('../bin', () => ({
  loadBin: vi.fn(),
  addToBin: vi.fn(),
  restoreFromBin: vi.fn(),
  permanentDeleteFromBin: vi.fn(),
  emptyBin: vi.fn(),
  purgeExpiredEntries: vi.fn(),
}));

// Mock share module
vi.mock('../share', () => ({
  createShareKey: vi.fn(),
  revokeShare: vi.fn(),
  reWrapForRecipients: vi.fn().mockResolvedValue({ failedRecipients: [] }),
}));

import * as sdkCore from '@cipherbox/sdk-core';
import * as binOps from '../bin';
import * as shareOps from '../share';

describe('CipherBoxClient - extended', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('renameItem', () => {
    it('renames and emits folder:updated', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.renameInFolder).mockReturnValue({
        updatedChildren: [
          {
            type: 'file',
            id: 'file1',
            name: 'renamed.txt',
            fileMetaIpnsName: 'k51file',
            ipnsPrivateKeyEncrypted: 'abc',
            createdAt: 0,
            modifiedAt: 0,
          },
        ],
        renamedChild: {
          type: 'file',
          id: 'file1',
          name: 'renamed.txt',
          fileMetaIpnsName: 'k51file',
          ipnsPrivateKeyEncrypted: 'abc',
          createdAt: 0,
          modifiedAt: 0,
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      await client.renameItem('folder-ipns', 'file1', 'renamed.txt');

      expect(sdkCore.renameInFolder).toHaveBeenCalledWith({
        children: expect.any(Array),
        childId: 'file1',
        newName: 'renamed.txt',
      });
      expect(events.some((e) => e.type === 'folder:updated')).toBe(true);
    });
  });

  describe('moveItem', () => {
    it('moves item between folders and emits two folder:updated events', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client, 'src-ipns');
      setupFolder(client, 'dest-ipns');

      vi.mocked(sdkCore.moveItem).mockReturnValue({
        updatedSourceChildren: [],
        updatedDestChildren: [
          {
            type: 'file',
            id: 'file1',
            name: 'test.txt',
            fileMetaIpnsName: 'k51file',
            ipnsPrivateKeyEncrypted: 'abc',
            createdAt: 0,
            modifiedAt: 0,
          },
        ],
        movedItem: {
          type: 'file',
          id: 'file1',
          name: 'test.txt',
          fileMetaIpnsName: 'k51file',
          ipnsPrivateKeyEncrypted: 'abc',
          createdAt: 0,
          modifiedAt: 0,
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      await client.moveItem('src-ipns', 'dest-ipns', 'file1');

      expect(sdkCore.moveItem).toHaveBeenCalled();
      const updatedEvents = events.filter((e) => e.type === 'folder:updated');
      expect(updatedEvents).toHaveLength(2);
    });

    it('throws when source folder not loaded', async () => {
      setupFolder(client, 'dest-ipns');
      await expect(client.moveItem('nonexistent', 'dest-ipns', 'file1')).rejects.toThrow(
        'Source folder not loaded'
      );
    });
  });

  describe('uploadFile', () => {
    it('uploads file and emits folder:updated + file:uploaded', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.uploadFile).mockResolvedValue({
        cid: 'bafyfile',
        encryptedSize: 100,
        fileMetaIpnsName: 'k51filemeta',
        ipnsRecord: {
          ipnsName: 'k51filemeta',
          recordBase64: 'mock-record',
          metadataCid: 'bafymeta',
        },
        ipnsPrivateKeyEncrypted: 'enc',
        fileKey: new Uint8Array(32).fill(0x42),
      });
      vi.mocked(sdkCore.addFilePointerToFolder).mockReturnValue({
        updatedChildren: [
          {
            type: 'file',
            id: 'file1',
            name: 'test.txt',
            fileMetaIpnsName: 'k51file',
            ipnsPrivateKeyEncrypted: 'abc',
            createdAt: 0,
            modifiedAt: 0,
          },
          {
            type: 'file',
            id: 'file2',
            name: 'new.txt',
            fileMetaIpnsName: 'k51filemeta',
            ipnsPrivateKeyEncrypted: 'enc',
            createdAt: 0,
            modifiedAt: 0,
          },
        ],
        filePointer: {
          type: 'file',
          id: 'file2',
          name: 'new.txt',
          fileMetaIpnsName: 'k51filemeta',
          ipnsPrivateKeyEncrypted: 'enc',
          createdAt: 0,
          modifiedAt: 0,
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      const result = await client.uploadFile(
        'folder-ipns',
        new Uint8Array([1, 2, 3]),
        'new.txt',
        'text/plain'
      );

      expect(result.cid).toBe('bafyfile');
      expect(events.some((e) => e.type === 'file:uploaded')).toBe(true);
      expect(events.some((e) => e.type === 'folder:updated')).toBe(true);
    });

    it('re-wraps file key for share recipients when shareCallbacks configured', async () => {
      const getCoveringShares = vi.fn().mockResolvedValue([
        {
          shareId: 'share-1',
          recipientPublicKey: '0xaabb',
          itemType: 'folder',
          ipnsName: 'folder-ipns',
          itemName: 'Shared',
        },
      ]);
      const addShareKeys = vi.fn().mockResolvedValue(undefined);

      const shareClient = new CipherBoxClient(
        createTestConfig({
          shareCallbacks: { getCoveringShares, addShareKeys },
        })
      );
      setupFolder(shareClient);

      vi.mocked(sdkCore.uploadFile).mockResolvedValue({
        cid: 'bafyfile',
        encryptedSize: 100,
        fileMetaIpnsName: 'k51filemeta',
        ipnsRecord: {
          ipnsName: 'k51filemeta',
          recordBase64: 'mock-record',
          metadataCid: 'bafymeta',
        },
        ipnsPrivateKeyEncrypted: 'enc',
        fileKey: new Uint8Array(32).fill(0x42),
      });
      vi.mocked(sdkCore.addFilePointerToFolder).mockReturnValue({
        updatedChildren: [],
        filePointer: {
          type: 'file',
          id: 'new-file-id',
          name: 'shared.txt',
          fileMetaIpnsName: 'k51filemeta',
          ipnsPrivateKeyEncrypted: 'enc',
          createdAt: 0,
          modifiedAt: 0,
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      await shareClient.uploadFile(
        'folder-ipns',
        new Uint8Array([1, 2, 3]),
        'shared.txt',
        'text/plain'
      );

      expect(getCoveringShares).toHaveBeenCalledWith('folder-ipns');
      // reWrapForRecipients (mocked) is called with the covering shares and addShareKeys callback
      expect(shareOps.reWrapForRecipients).toHaveBeenCalledWith(
        expect.objectContaining({
          coveringShares: expect.arrayContaining([expect.objectContaining({ shareId: 'share-1' })]),
          addShareKeysFn: addShareKeys,
        })
      );
    });

    it('skips re-wrapping when no shareCallbacks configured', async () => {
      setupFolder(client);

      vi.mocked(sdkCore.uploadFile).mockResolvedValue({
        cid: 'bafyfile',
        encryptedSize: 100,
        fileMetaIpnsName: 'k51filemeta',
        ipnsRecord: {
          ipnsName: 'k51filemeta',
          recordBase64: 'mock-record',
          metadataCid: 'bafymeta',
        },
        ipnsPrivateKeyEncrypted: 'enc',
        fileKey: new Uint8Array(32).fill(0x42),
      });
      vi.mocked(sdkCore.addFilePointerToFolder).mockReturnValue({
        updatedChildren: [],
        filePointer: {
          type: 'file',
          id: 'f1',
          name: 'no-share.txt',
          fileMetaIpnsName: 'k51filemeta',
          ipnsPrivateKeyEncrypted: 'enc',
          createdAt: 0,
          modifiedAt: 0,
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      // Should not throw — no shareCallbacks means no re-wrapping
      await client.uploadFile(
        'folder-ipns',
        new Uint8Array([1, 2, 3]),
        'no-share.txt',
        'text/plain'
      );

      // The reWrapForRecipients mock should NOT have been called
      const { reWrapForRecipients } = await import('../share');
      expect(reWrapForRecipients).not.toHaveBeenCalled();
    });

    it('skips re-wrapping when no covering shares exist', async () => {
      const getCoveringShares = vi.fn().mockResolvedValue([]);
      const addShareKeys = vi.fn();

      const shareClient = new CipherBoxClient(
        createTestConfig({
          shareCallbacks: { getCoveringShares, addShareKeys },
        })
      );
      setupFolder(shareClient);

      vi.mocked(sdkCore.uploadFile).mockResolvedValue({
        cid: 'bafyfile',
        encryptedSize: 100,
        fileMetaIpnsName: 'k51filemeta',
        ipnsRecord: {
          ipnsName: 'k51filemeta',
          recordBase64: 'mock-record',
          metadataCid: 'bafymeta',
        },
        ipnsPrivateKeyEncrypted: 'enc',
        fileKey: new Uint8Array(32).fill(0x42),
      });
      vi.mocked(sdkCore.addFilePointerToFolder).mockReturnValue({
        updatedChildren: [],
        filePointer: {
          type: 'file',
          id: 'f1',
          name: 'no-shares.txt',
          fileMetaIpnsName: 'k51filemeta',
          ipnsPrivateKeyEncrypted: 'enc',
          createdAt: 0,
          modifiedAt: 0,
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      await shareClient.uploadFile(
        'folder-ipns',
        new Uint8Array([1, 2, 3]),
        'no-shares.txt',
        'text/plain'
      );

      expect(getCoveringShares).toHaveBeenCalledWith('folder-ipns');
      expect(addShareKeys).not.toHaveBeenCalled();
    });

    it('clears fileKey after re-wrapping even on failure', async () => {
      const getCoveringShares = vi.fn().mockRejectedValue(new Error('Share discovery failed'));
      const addShareKeys = vi.fn();
      const fileKey = new Uint8Array(32).fill(0x42);

      const shareClient = new CipherBoxClient(
        createTestConfig({
          shareCallbacks: { getCoveringShares, addShareKeys },
        })
      );
      setupFolder(shareClient);

      vi.mocked(sdkCore.uploadFile).mockResolvedValue({
        cid: 'bafyfile',
        encryptedSize: 100,
        fileMetaIpnsName: 'k51filemeta',
        ipnsRecord: {
          ipnsName: 'k51filemeta',
          recordBase64: 'mock-record',
          metadataCid: 'bafymeta',
        },
        ipnsPrivateKeyEncrypted: 'enc',
        fileKey,
      });
      vi.mocked(sdkCore.addFilePointerToFolder).mockReturnValue({
        updatedChildren: [],
        filePointer: {
          type: 'file',
          id: 'f1',
          name: 'fail.txt',
          fileMetaIpnsName: 'k51filemeta',
          ipnsPrivateKeyEncrypted: 'enc',
          createdAt: 0,
          modifiedAt: 0,
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      // Upload should still succeed even if re-wrapping fails
      const result = await shareClient.uploadFile(
        'folder-ipns',
        new Uint8Array([1, 2, 3]),
        'fail.txt',
        'text/plain'
      );

      expect(result.cid).toBe('bafyfile');
      // fileKey should be zeroed
      expect(fileKey.every((b) => b === 0)).toBe(true);
    });
  });

  describe('downloadFromIpns', () => {
    it('resolves file metadata and downloads content', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
        metadata: {
          version: 'v1',
          cid: 'bafycontent',
          fileKeyEncrypted: 'abc',
          fileIv: 'def',
          size: 1024,
          mimeType: 'application/octet-stream',
          encryptionMode: 'GCM',
          createdAt: 1700000000000,
          modifiedAt: 1700000000000,
        },
        metadataCid: 'bafymetacid',
      });
      vi.mocked(sdkCore.downloadAndDecrypt).mockResolvedValue(
        new Uint8Array([72, 101, 108, 108, 111])
      );

      const result = await client.downloadFromIpns('k51filemeta', new Uint8Array(32));

      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
      expect(events.some((e) => e.type === 'file:downloaded')).toBe(true);
    });
  });

  describe('bin operations', () => {
    it('loadBin sets binState and emits bin:updated', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [
          {
            id: '1',
            itemType: 'file',
            name: 'deleted.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      });

      const result = await client.loadBin();

      expect(result.entries).toHaveLength(1);
      expect(events.some((e) => e.type === 'bin:updated')).toBe(true);
    });

    it('deleteToBin throws BinNotLoadedError when bin not loaded', async () => {
      setupFolder(client);
      await expect(client.deleteToBin('folder-ipns', 'file1', 'My Vault')).rejects.toThrow(
        BinNotLoadedError
      );
    });

    it('deleteToBin removes item and emits events', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      const child = setupFolder(client);

      // Load bin first
      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [],
        sequenceNumber: 0,
        ipnsName: 'k51bin',
      });
      await client.loadBin();
      vi.clearAllMocks();

      vi.mocked(binOps.addToBin).mockResolvedValue({
        removedItem: child,
        updatedBinState: {
          entries: [
            {
              id: '1',
              itemType: 'file',
              name: 'test.txt',
              originalParentIpnsName: 'folder-ipns',
              originalPath: 'My Vault',
              deletedAt: Date.now(),
              size: 0,
              mimeType: '',
            },
          ],
          sequenceNumber: 1,
          ipnsName: 'k51bin',
        },
      });

      await client.deleteToBin('folder-ipns', 'file1', 'My Vault');

      expect(binOps.addToBin).toHaveBeenCalled();
      expect(events.some((e) => e.type === 'folder:updated')).toBe(true);
      expect(events.some((e) => e.type === 'bin:updated')).toBe(true);
    });

    it('restoreFromBin emits events', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client, 'target-ipns');

      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'x.txt',
            originalParentIpnsName: 'target-ipns',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      });
      await client.loadBin();
      vi.clearAllMocks();

      vi.mocked(binOps.restoreFromBin).mockResolvedValue({
        restoredItem: {
          type: 'file',
          id: 'file1',
          name: 'x.txt',
          fileMetaIpnsName: 'k51',
          ipnsPrivateKeyEncrypted: '',
          createdAt: 0,
          modifiedAt: 0,
        },
        updatedBinState: { entries: [], sequenceNumber: 2, ipnsName: 'k51bin' },
      });

      await client.restoreFromBin('e1', 'target-ipns');

      expect(events.some((e) => e.type === 'bin:updated')).toBe(true);
    });

    it('permanentDelete emits bin:updated', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'x.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      });
      await client.loadBin();

      vi.mocked(binOps.permanentDeleteFromBin).mockResolvedValue({
        updatedBinState: { entries: [], sequenceNumber: 2, ipnsName: 'k51bin' },
      });

      await client.permanentDelete('e1');

      expect(events.some((e) => e.type === 'bin:updated')).toBe(true);
    });

    it('emptyBin clears all entries', async () => {
      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'x.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      });
      await client.loadBin();

      vi.mocked(binOps.emptyBin).mockResolvedValue({
        updatedBinState: { entries: [], sequenceNumber: 2, ipnsName: 'k51bin' },
      });

      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      await client.emptyBin();

      const binEvent = events.find(
        (e): e is Extract<SdkEvent, { type: 'bin:updated' }> => e.type === 'bin:updated'
      );
      expect(binEvent).toBeDefined();
      expect(binEvent?.entries).toEqual([]);
    });

    it('purgeExpired validates retentionDays and emits bin:updated', async () => {
      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [{ id: 'e1', name: 'old.txt', deletedAt: 0, type: 'file' }],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      });
      await client.loadBin();

      vi.mocked(binOps.purgeExpiredEntries).mockResolvedValue({
        purgedCount: 1,
        updatedState: { entries: [], sequenceNumber: 2, ipnsName: 'k51bin' },
      });

      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      const purged = await client.purgeExpired(30);

      expect(purged).toBe(1);
      expect(binOps.purgeExpiredEntries).toHaveBeenCalledWith(
        expect.objectContaining({ retentionDays: 30 })
      );
      expect(events.find((e) => e.type === 'bin:updated')).toBeDefined();
    });

    it('purgeExpired throws TypeError for non-finite input', async () => {
      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      });
      await client.loadBin();

      await expect(client.purgeExpired(NaN)).rejects.toThrow(TypeError);
      await expect(client.purgeExpired(Infinity)).rejects.toThrow(TypeError);
    });

    it('purgeExpired normalizes negative and fractional days', async () => {
      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      });
      await client.loadBin();

      vi.mocked(binOps.purgeExpiredEntries).mockResolvedValue({
        purgedCount: 0,
        updatedState: { entries: [], sequenceNumber: 1, ipnsName: 'k51bin' },
      });

      await client.purgeExpired(-5);
      expect(binOps.purgeExpiredEntries).toHaveBeenCalledWith(
        expect.objectContaining({ retentionDays: 0 })
      );

      await client.purgeExpired(7.8);
      expect(binOps.purgeExpiredEntries).toHaveBeenCalledWith(
        expect.objectContaining({ retentionDays: 7 })
      );
    });

    it('purgeExpired throws BinNotLoadedError when bin not loaded', async () => {
      await expect(client.purgeExpired(30)).rejects.toThrow(BinNotLoadedError);
    });
  });

  describe('share operations', () => {
    it('shareFolder wraps key for recipient', async () => {
      setupFolder(client);

      vi.mocked(shareOps.createShareKey).mockResolvedValue({ encryptedKey: 'wrapped-hex' });

      const result = await client.shareFolder('folder-ipns', new Uint8Array(33).fill(9));

      expect(result.encryptedKey).toBe('wrapped-hex');
      expect(shareOps.createShareKey).toHaveBeenCalled();
    });

    it('shareFolder throws when folder not loaded', async () => {
      await expect(client.shareFolder('nonexistent', new Uint8Array(33))).rejects.toThrow(
        'Folder not loaded'
      );
    });

    it('revokeShare delegates to share module', async () => {
      vi.mocked(shareOps.revokeShare).mockResolvedValue(undefined);
      const revokeFn = vi.fn();

      await client.revokeShare('share-123', revokeFn);

      expect(shareOps.revokeShare).toHaveBeenCalledWith({
        shareId: 'share-123',
        revokeShareFn: revokeFn,
      });
    });
  });

  describe('state management', () => {
    it('hasFolder returns correct state', () => {
      expect(client.hasFolder('folder-ipns')).toBe(false);
      setupFolder(client);
      expect(client.hasFolder('folder-ipns')).toBe(true);
    });

    it('registerFolder adds to folder tree', () => {
      client.registerFolder(
        'new-ipns',
        new Uint8Array(32),
        { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        [],
        0n
      );
      expect(client.hasFolder('new-ipns')).toBe(true);
    });

    it('destroy zeros internal key copies without mutating caller buffers', () => {
      const config = createTestConfig();
      const originalPrivKey = new Uint8Array(config.vaultKeypair.privateKey);
      const originalPubKey = new Uint8Array(config.vaultKeypair.publicKey);
      const originalRootKey = new Uint8Array(config.rootFolderKey);
      const c = new CipherBoxClient(config);
      c.destroy();

      // Caller-provided buffers should NOT be zeroed
      expect(config.vaultKeypair.privateKey).toEqual(originalPrivKey);
      expect(config.vaultKeypair.publicKey).toEqual(originalPubKey);
      expect(config.rootFolderKey).toEqual(originalRootKey);
    });
  });

  describe('BinNotLoadedError', () => {
    it('is an instance of Error with correct name', () => {
      const err = new BinNotLoadedError();
      expect(err).toBeInstanceOf(Error);
      expect(err.name).toBe('BinNotLoadedError');
      expect(err.message).toBe('Bin not loaded');
    });
  });
});
