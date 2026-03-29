import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadBin, addToBin, restoreFromBin, permanentDeleteFromBin, emptyBin } from '../bin';
import type { BinOperationContext, BinState } from '../bin';
import { FolderTree } from '../state/folder-tree';

// Mock sdk-core
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    deleteFromFolder: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    addToIpfs: vi.fn(),
    unpinFromIpfs: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

// Mock @cipherbox/core
vi.mock('@cipherbox/core', () => ({
  encryptBinMetadata: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
  decryptBinMetadata: vi.fn().mockResolvedValue({ version: 'v1', sequenceNumber: 1, entries: [] }),
  deriveBinIpnsKeypair: vi.fn().mockResolvedValue({
    ipnsName: 'k51bin',
    privateKey: new Uint8Array(64).fill(5),
    publicKey: new Uint8Array(32).fill(6),
  }),
}));

// Mock @cipherbox/crypto
vi.mock('@cipherbox/crypto', () => ({
  bytesToHex: vi.fn().mockReturnValue('aabb'),
  hexToBytes: vi.fn().mockReturnValue(new Uint8Array(32)),
  wrapKey: vi.fn().mockResolvedValue(new Uint8Array([0xaa])),
}));

import * as sdkCore from '@cipherbox/sdk-core';

const binCtx: BinOperationContext = {
  ctx: { apiUrl: 'http://localhost:3000', getAccessToken: async () => 'token' },
  userPrivateKey: new Uint8Array(32).fill(1),
  userPublicKey: new Uint8Array(33).fill(2),
  rootFolderKey: new Uint8Array(32).fill(3),
};

describe('bin operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('loadBin', () => {
    it('auto-repairs when no IPNS record exists (publishes empty bin with sequenceNumber 1)', async () => {
      // First call: loadBinMetadataInternal -> resolveIpnsRecord returns null (trigger auto-repair)
      // Second call: inside saveBinMetadata -> publishWithVerify -> resolveIpnsRecord returns valid (verify success)
      vi.mocked(sdkCore.resolveIpnsRecord)
        .mockResolvedValueOnce(null) // initial load attempt
        .mockResolvedValueOnce({ cid: 'bafyempty', sequenceNumber: 1n, signatureVerified: true }); // verify after publish
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafyempty', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 1n,
      });

      const result = await loadBin({ binCtx });

      expect(result.entries).toEqual([]);
      expect(result.sequenceNumber).toBe(1);
      expect(result.ipnsName).toBe('k51bin');
      // Auto-repair should have published
      expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalled();
      expect(sdkCore.addToIpfs).toHaveBeenCalled();
    });

    it('auto-repair calls saveBinMetadata which uses publishWithVerify', async () => {
      // resolveIpnsRecord: null on initial load, then valid on verify call
      vi.mocked(sdkCore.resolveIpnsRecord)
        .mockResolvedValueOnce(null) // initial load attempt
        .mockResolvedValueOnce({ cid: 'bafyempty', sequenceNumber: 1n, signatureVerified: true }); // verify after publish
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafyempty', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 1n,
      });

      await loadBin({ binCtx });

      // createAndPublishIpnsRecord called once (publish)
      expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalledTimes(1);
      // resolveIpnsRecord called at least twice: initial load + verify after publish
      expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledTimes(2);
    });

    it('returns existing bin state when IPNS record found', async () => {
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 3n,
        signatureVerified: true,
      });
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(new Uint8Array([1]));

      const { decryptBinMetadata } = await import('@cipherbox/core');
      vi.mocked(decryptBinMetadata).mockResolvedValue({
        version: 'v1',
        sequenceNumber: 3,
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
      });

      const result = await loadBin({ binCtx });

      expect(result.entries).toHaveLength(1);
      expect(result.sequenceNumber).toBe(3);
    });
  });

  describe('addToBin', () => {
    it('removes item from folder and adds to bin', async () => {
      const folderTree = new FolderTree();
      const child = {
        type: 'file' as const,
        id: 'f1',
        name: 'doc.txt',
        fileMetaIpnsName: 'k51f',
        ipnsPrivateKeyEncrypted: 'abc',
        createdAt: 0,
        modifiedAt: 0,
      };

      folderTree.set('folder-ipns', {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [child],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
        updatedChildren: [],
        removedItem: child,
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 1n,
      });
      // publishWithVerify will call resolveIpnsRecord to verify
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 1n,
        signatureVerified: true,
      });

      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      const result = await addToBin({
        folderIpnsName: 'folder-ipns',
        childId: 'f1',
        parentPath: 'My Vault',
        folderTree,
        binState,
        binCtx,
      });

      expect(result.removedItem).toEqual(child);
      expect(result.updatedBinState.entries).toHaveLength(1);
      expect(result.updatedBinState.entries[0].name).toBe('doc.txt');
      expect(result.updatedBinState.sequenceNumber).toBe(1);
    });

    it('throws when folder not loaded', async () => {
      const folderTree = new FolderTree();
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        addToBin({
          folderIpnsName: 'nonexistent',
          childId: 'f1',
          parentPath: '/',
          folderTree,
          binState,
          binCtx,
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });

  describe('restoreFromBin', () => {
    it('restores item to target folder', async () => {
      const folderTree = new FolderTree();
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: new Uint8Array(32),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      // publishWithVerify will call resolveIpnsRecord to verify
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 2n,
        signatureVerified: true,
      });

      const fileChild = {
        type: 'file' as const,
        id: 'f1',
        name: 'doc.txt',
        fileMetaIpnsName: 'k51f',
        ipnsPrivateKeyEncrypted: 'abc',
        createdAt: 0,
        modifiedAt: 0,
      };
      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'doc.txt',
            originalParentIpnsName: 'target-ipns',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            filePointer: fileChild,
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      const result = await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState,
        binCtx,
      });

      expect(result.restoredItem.name).toBe('doc.txt');
      expect(result.updatedBinState.entries).toHaveLength(0);
    });

    it('throws when bin entry not found', async () => {
      const folderTree = new FolderTree();
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        restoreFromBin({
          entryId: 'nonexistent',
          targetFolderIpnsName: 'k51',
          folderTree,
          binState,
          binCtx,
        })
      ).rejects.toThrow('Bin entry not found');
    });
  });

  describe('permanentDeleteFromBin', () => {
    it('removes entry from bin and unpins CID', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      // publishWithVerify will call resolveIpnsRecord to verify
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 2n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'x.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 100,
            mimeType: '',
            contentCid: 'bafycontent',
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      const result = await permanentDeleteFromBin({ entryId: 'e1', binState, binCtx });

      expect(result.updatedBinState.entries).toHaveLength(0);
      expect(sdkCore.unpinFromIpfs).toHaveBeenCalledWith(binCtx.ctx, 'bafycontent');
    });
  });

  describe('emptyBin', () => {
    it('removes all entries and publishes empty bin', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 3n,
      });
      // publishWithVerify will call resolveIpnsRecord to verify
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 3n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'a.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            contentCid: 'bafya',
          },
          {
            id: 'e2',
            itemType: 'file',
            name: 'b.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
          },
        ],
        sequenceNumber: 2,
        ipnsName: 'k51bin',
      };

      const result = await emptyBin({ binState, binCtx });

      expect(result.updatedBinState.entries).toHaveLength(0);
      expect(result.updatedBinState.sequenceNumber).toBe(3);
    });

    it('publishWithVerify retries when verify fails', async () => {
      vi.useFakeTimers();

      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      // Verify fails first time, succeeds second time
      vi.mocked(sdkCore.resolveIpnsRecord)
        .mockResolvedValueOnce(null) // first verify fails
        .mockResolvedValueOnce({ cid: 'bafybin', sequenceNumber: 2n, signatureVerified: true }); // second verify succeeds

      const binState: BinState = {
        entries: [],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      const resultPromise = emptyBin({ binState, binCtx });

      // Advance timers to handle backoff delay
      await vi.advanceTimersByTimeAsync(2000);

      const result = await resultPromise;

      expect(result.updatedBinState.sequenceNumber).toBe(2);
      // Publish called once (no re-publish on verify failure)
      expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalledTimes(1);
      // resolveIpnsRecord called twice: first verify fails, second succeeds
      expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledTimes(2);

      vi.useRealTimers();
    });
  });
});
