import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadBin, addToBin, restoreFromBin, permanentDeleteFromBin, emptyBin } from '../bin';
import type { BinOperationContext, BinState } from '../bin';
import { FolderTree } from '../state/folder-tree';
import type { FolderChild } from '@cipherbox/core';

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
    resolveFileMetadata: vi.fn(),
    updateFileMetadata: vi.fn(),
    loadFolderMetadata: vi.fn(),
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
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(64).fill(7)),
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
}));

import * as sdkCore from '@cipherbox/sdk-core';
import { unwrapKey } from '@cipherbox/crypto';

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
    it('returns in-memory empty state WITHOUT publishing when no IPNS record exists', async () => {
      // A null resolve is NOT a reliable "bin is empty" signal — publishing an
      // empty record here is destructive (the bin publish path carries no
      // expectedSequenceNumber, so the API blindly increments and overwrites the
      // real record's CID, wiping every entry). loadBin must therefore return an
      // in-memory empty state and NEVER publish on a null resolve. The bounded
      // retry resolves null on every attempt here (genuinely-new bin).
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

      const result = await loadBin({ binCtx });

      // Empty in-memory state with seq 0 so the first addToBin publishes at
      // 0 + 1 = 1, matching the API create-path.
      expect(result.entries).toEqual([]);
      expect(result.sequenceNumber).toBe(0);
      expect(result.ipnsName).toBe('k51bin');
      // Critically: NO publish happened — no empty bin was written.
      expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
      expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
    });

    it('retries the resolve before falling back to empty state, without publishing', async () => {
      // Bounded retry on a persistent null: still falls back to the empty
      // in-memory state, and still never publishes.
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

      const result = await loadBin({ binCtx });

      // resolveIpnsRecord retried up to the bounded maximum (6 attempts).
      expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledTimes(6);
      expect(result.sequenceNumber).toBe(0);
      // No publish on any attempt.
      expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
    });

    it('does NOT clobber a real record when the first resolve is a transient (cold-cache) null', async () => {
      // The first resolve misses (e.g. cold resolve cache right after a reload),
      // but the bin actually holds a deleted entry at sequenceNumber 2. The bounded
      // retry must surface it WITHOUT publishing the destructive empty-bin record.
      vi.mocked(sdkCore.resolveIpnsRecord)
        .mockResolvedValueOnce(null) // transient miss on initial load
        .mockResolvedValueOnce({ cid: 'bafyreal', sequenceNumber: 2n, signatureVerified: true }); // retry finds the real record
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(new Uint8Array([9]));
      const { decryptBinMetadata } = await import('@cipherbox/core');
      vi.mocked(decryptBinMetadata).mockResolvedValue({
        version: 'v1',
        sequenceNumber: 2,
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'f.txt',
            originalParentIpnsName: 'sub-ipns',
            originalPath: 'My Vault / sub',
            deletedAt: Date.now(),
            size: 0,
            mimeType: '',
          },
        ],
      });

      const result = await loadBin({ binCtx });

      expect(result.entries.map((e) => e.name)).toEqual(['f.txt']);
      expect(result.sequenceNumber).toBe(2);
      // Critically: no empty-bin publish happened, so the real record is preserved.
      expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
      expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
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

  describe.skip('addToBin — TODO(phase 65)', () => {
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
        publishedChildren: [],
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
      // The file's own FileMetadata (for content/version CID capture).
      vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
        metadata: {
          version: 'v1',
          cid: 'bafycontent',
          size: 100,
          fileKeyEncrypted: 'aa',
          fileIv: 'bb',
          mimeType: 'text/plain',
          createdAt: 0,
          modifiedAt: 0,
          versions: [{ cid: 'bafyv1', size: 50 } as never],
        },
        metadataCid: 'bafymeta',
      } as never);

      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };
      const revokeSharesForItemsFn = vi.fn().mockResolvedValue(undefined);

      const result = await addToBin({
        folderIpnsName: 'folder-ipns',
        childId: 'f1',
        parentPath: 'My Vault',
        folderTree,
        binState,
        binCtx,
        revokeSharesForItemsFn,
      });

      expect(result.removedItem).toEqual(child);
      expect(result.updatedBinState.entries).toHaveLength(1);
      const entry = result.updatedBinState.entries[0];
      expect(entry.name).toBe('doc.txt');
      expect(result.updatedBinState.sequenceNumber).toBe(1);
      // Content + version CIDs captured for later unpin.
      expect(entry.contentCid).toBe('bafycontent');
      expect(entry.versionCids).toEqual([{ cid: 'bafyv1', size: 50 }]);
      // Shares revoked for the file's own IPNS name BEFORE the destructive publish.
      expect(revokeSharesForItemsFn).toHaveBeenCalledWith(['k51f']);
      const revokeOrder = revokeSharesForItemsFn.mock.invocationCallOrder[0];
      const publishOrder = vi.mocked(sdkCore.updateFolderMetadataAndPublish).mock
        .invocationCallOrder[0];
      expect(revokeOrder).toBeLessThan(publishOrder);
    });

    it('aborts the delete (no folder publish) when share revocation fails', async () => {
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
      vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
        metadata: { version: 'v1', cid: 'bafycontent', size: 100 },
        metadataCid: 'm',
      } as never);

      // Revoke always rejects -> revokeSharesForItems exhausts retries and throws.
      const revokeSharesForItemsFn = vi.fn().mockRejectedValue(new Error('boom'));
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        addToBin({
          folderIpnsName: 'folder-ipns',
          childId: 'f1',
          parentPath: 'My Vault',
          folderTree,
          binState,
          binCtx,
          revokeSharesForItemsFn,
        })
      ).rejects.toThrow('boom');

      // The destructive folder mutation must NOT have run.
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
    });

    it('walks the deleted folder subtree (fail-closed) and stores descendant CIDs + revokes all node ipnsNames', async () => {
      const folderTree = new FolderTree();
      const folderChild = {
        type: 'folder' as const,
        id: 'sub1',
        name: 'Sub',
        ipnsName: 'k51sub',
        ipnsPrivateKeyEncrypted: 'aa',
        folderKeyEncrypted: 'bb',
        createdAt: 0,
        modifiedAt: 0,
      };
      folderTree.set('folder-ipns', {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [folderChild],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
        updatedChildren: [],
        removedItem: folderChild,
      });
      // Subtree: k51sub contains one file (k51subfile).
      vi.mocked(sdkCore.loadFolderMetadata).mockImplementation(async ({ ipnsName }) => {
        if (ipnsName === 'k51sub') {
          return {
            metadata: {
              version: 'v2',
              children: [
                {
                  type: 'file',
                  id: 'ff',
                  name: 'inner.txt',
                  fileMetaIpnsName: 'k51subfile',
                  createdAt: 0,
                  modifiedAt: 0,
                },
              ],
            },
            sequenceNumber: 1n,
            cid: 'cid-sub',
          } as never;
        }
        return null;
      });
      // The descendant file's content + version CIDs.
      vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
        metadata: {
          version: 'v1',
          cid: 'bafyinner',
          size: 10,
          versions: [{ cid: 'bafyiv', size: 5 }],
        },
        metadataCid: 'm',
      } as never);
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 1n,
      });
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 1n,
        signatureVerified: true,
      });

      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };
      const revokeSharesForItemsFn = vi.fn().mockResolvedValue(undefined);

      const result = await addToBin({
        folderIpnsName: 'folder-ipns',
        childId: 'sub1',
        parentPath: 'My Vault',
        folderTree,
        binState,
        binCtx,
        revokeSharesForItemsFn,
      });

      const entry = result.updatedBinState.entries[0];
      expect(entry.itemType).toBe('folder');
      // Descendant content + version CIDs captured for the whole subtree.
      expect(entry.descendantCids).toEqual([
        { cid: 'bafyinner', size: 10 },
        { cid: 'bafyiv', size: 5 },
      ]);
      // Every node ipnsName in the subtree revoked (folder + descendant file).
      expect(revokeSharesForItemsFn).toHaveBeenCalledWith(['k51sub', 'k51subfile']);
    });

    it('aborts a folder delete (no publish) when a subtree folder cannot be enumerated (fail-closed)', async () => {
      const folderTree = new FolderTree();
      const folderChild = {
        type: 'folder' as const,
        id: 'sub1',
        name: 'Sub',
        ipnsName: 'k51sub',
        ipnsPrivateKeyEncrypted: 'aa',
        folderKeyEncrypted: 'bb',
        createdAt: 0,
        modifiedAt: 0,
      };
      folderTree.set('folder-ipns', {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [folderChild],
        metadata: null,
        lastLoadedAt: Date.now(),
      });
      vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
        updatedChildren: [],
        removedItem: folderChild,
      });
      // The deleted folder's own metadata won't resolve -> walk throws.
      vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

      const revokeSharesForItemsFn = vi.fn().mockResolvedValue(undefined);
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        addToBin({
          folderIpnsName: 'folder-ipns',
          childId: 'sub1',
          parentPath: 'My Vault',
          folderTree,
          binState,
          binCtx,
          revokeSharesForItemsFn,
        })
      ).rejects.toThrow(/Cannot enumerate deleted subtree/);

      // Fail-closed: no revoke, no destructive folder publish.
      expect(revokeSharesForItemsFn).not.toHaveBeenCalled();
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
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

  describe.skip('restoreFromBin — TODO(phase 65)', () => {
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
        publishedChildren: [],
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

    it('skips file-metadata re-encryption when restoring in place (target === original parent)', async () => {
      const folderTree = new FolderTree();
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: new Uint8Array(32).fill(1),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

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
            filePointer: {
              type: 'file',
              id: 'f1',
              name: 'doc.txt',
              fileMetaIpnsName: 'k51f',
              ipnsPrivateKeyEncrypted: 'abc',
              createdAt: 0,
              modifiedAt: 0,
            },
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState,
        binCtx,
      });

      expect(sdkCore.resolveFileMetadata).not.toHaveBeenCalled();
      expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
    });

    it('re-encrypts file metadata from the original parent key to the target key when restoring to a different folder', async () => {
      const sourceKey = new Uint8Array(32).fill(0x11);
      const targetKey = new Uint8Array(32).fill(0x22);
      const folderTree = new FolderTree();
      folderTree.set('source-ipns', {
        ipnsName: 'source-ipns',
        folderKey: sourceKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: targetKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      const currentMetadata = { version: 'v1', name: 'doc.txt' } as never;
      vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
        metadata: currentMetadata,
      } as never);
      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({} as never);
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'doc.txt',
            originalParentIpnsName: 'source-ipns',
            originalPath: '/old',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            filePointer: {
              type: 'file',
              id: 'f1',
              name: 'doc.txt',
              fileMetaIpnsName: 'k51f',
              ipnsPrivateKeyEncrypted: 'abc',
              createdAt: 0,
              modifiedAt: 0,
            },
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState,
        binCtx,
      });

      // Decrypt the existing record with the ORIGINAL parent's key...
      expect(sdkCore.resolveFileMetadata).toHaveBeenCalledWith('k51f', sourceKey, binCtx.ctx);
      // ...and re-publish it under the DESTINATION folder's key, without versioning.
      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      const arg = vi.mocked(sdkCore.updateFileMetadata).mock.calls[0][0];
      expect(arg.folderKey).toEqual(targetKey);
      expect(arg.fileMetaIpnsName).toBe('k51f');
      expect(arg.createVersion).toBe(false);
    });

    it('re-encrypts using the captured original folder key when the original parent is gone (delete file, delete parent, restore elsewhere)', async () => {
      // User scenario: delete ~/a/b/c.txt, then delete ~/a/b/, then restore
      // c.txt to a different existing folder. The original parent (b) is no
      // longer in the folder tree, but its folderKey was captured on the entry
      // at delete time, so re-encryption still succeeds.
      const targetKey = new Uint8Array(32).fill(0x22);
      const folderTree = new FolderTree();
      // Only the target is loaded — the original parent 'b' is NOT in the tree.
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: targetKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
        metadata: { version: 'v1', name: 'c.txt' },
      } as never);
      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({} as never);
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'c.txt',
            originalParentIpnsName: 'b-ipns-deleted',
            originalPath: '/a/b',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            originalFolderKeyEncrypted: 'cafe'.repeat(16),
            filePointer: {
              type: 'file',
              id: 'f1',
              name: 'c.txt',
              fileMetaIpnsName: 'k51f',
              ipnsPrivateKeyEncrypted: 'abc',
              createdAt: 0,
              modifiedAt: 0,
            },
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      // Must NOT throw despite the original parent being absent from the tree.
      await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState,
        binCtx,
      });

      // Re-encryption ran: read the existing record, re-publish under the target key.
      expect(sdkCore.resolveFileMetadata).toHaveBeenCalledTimes(1);
      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      const arg = vi.mocked(sdkCore.updateFileMetadata).mock.calls[0][0];
      expect(arg.folderKey).toEqual(targetKey);
      expect(arg.createVersion).toBe(false);
      // The captured key was unwrapped (folder key + file IPNS key = 2 unwraps).
      expect(unwrapKey).toHaveBeenCalledTimes(2);
    });

    it('publishes the target folder before re-encrypting the file metadata (reorder)', async () => {
      // The target listing must be durable BEFORE the metadata is re-keyed, so a
      // re-key failure leaves the file readable from the bin (source key) and listed
      // in the target — never stranded under the dest key with no folder pointing at it.
      const sourceKey = new Uint8Array(32).fill(0x11);
      const targetKey = new Uint8Array(32).fill(0x22);
      const folderTree = new FolderTree();
      folderTree.set('source-ipns', {
        ipnsName: 'source-ipns',
        folderKey: sourceKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: targetKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      const order: string[] = [];
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async () => {
        order.push('publish');
        return { cid: 'bafynew', newSequenceNumber: 2n, publishedChildren: [] };
      });
      vi.mocked(sdkCore.resolveFileMetadata).mockImplementation(async () => {
        order.push('reencrypt');
        return { metadata: { version: 'v1', name: 'doc.txt' } } as never;
      });
      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({} as never);
      // bin publish (saveBinMetadata)
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
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
            name: 'doc.txt',
            originalParentIpnsName: 'source-ipns',
            originalPath: '/old',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            filePointer: {
              type: 'file',
              id: 'f1',
              name: 'doc.txt',
              fileMetaIpnsName: 'k51f',
              ipnsPrivateKeyEncrypted: 'abc',
              createdAt: 0,
              modifiedAt: 0,
            },
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState,
        binCtx,
      });

      expect(order).toEqual(['publish', 'reencrypt']);
    });

    it('completes idempotently when the metadata was already re-keyed (retry after a partial restore)', async () => {
      // A prior partial restore already re-keyed the record to the target. The
      // source-key resolve now fails; the helper confirms the record under the
      // target key and treats the re-encryption as done — restore still completes.
      const sourceKey = new Uint8Array(32).fill(0x11);
      const targetKey = new Uint8Array(32).fill(0x22);
      const folderTree = new FolderTree();
      folderTree.set('source-ipns', {
        ipnsName: 'source-ipns',
        folderKey: sourceKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: targetKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      vi.mocked(sdkCore.resolveFileMetadata)
        .mockRejectedValueOnce(
          Object.assign(new Error('Decryption failed'), { code: 'DECRYPTION_FAILED' })
        )
        .mockResolvedValueOnce({ metadata: { version: 'v1' } } as never);
      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({} as never);
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
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
            name: 'doc.txt',
            originalParentIpnsName: 'source-ipns',
            originalPath: '/old',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            filePointer: {
              type: 'file',
              id: 'f1',
              name: 'doc.txt',
              fileMetaIpnsName: 'k51f',
              ipnsPrivateKeyEncrypted: 'abc',
              createdAt: 0,
              modifiedAt: 0,
            },
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

      // Restore completed (entry removed) without re-publishing the file metadata.
      expect(result.updatedBinState.entries).toHaveLength(0);
      expect(sdkCore.resolveFileMetadata).toHaveBeenCalledTimes(2); // source then target
      expect(vi.mocked(sdkCore.resolveFileMetadata).mock.calls[0][1]).toEqual(sourceKey);
      expect(vi.mocked(sdkCore.resolveFileMetadata).mock.calls[1][1]).toEqual(targetKey);
      expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
    });

    it('does not duplicate the listing when the target already contains the child (retry after a partial restore)', async () => {
      // A prior attempt published the child into the target, then failed at the
      // re-key (step 5b) or bin removal (step 6) — the bin entry survives, so the UI
      // retries. The retry must REPLACE the existing listing, not append a second
      // entry with the same id (the no-conflict publish path does not dedup by id).
      const sourceKey = new Uint8Array(32).fill(0x11);
      const targetKey = new Uint8Array(32).fill(0x22);
      const existingChild = {
        type: 'file' as const,
        id: 'f1',
        name: 'doc.txt',
        fileMetaIpnsName: 'k51f',
        ipnsPrivateKeyEncrypted: 'abc',
        createdAt: 0,
        modifiedAt: 0,
      };
      const folderTree = new FolderTree();
      folderTree.set('source-ipns', {
        ipnsName: 'source-ipns',
        folderKey: sourceKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: targetKey,
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [existingChild], // already published by attempt 1
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      let publishedChildren: FolderChild[] | undefined;
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (p) => {
        publishedChildren = p.children;
        return { cid: 'bafynew', newSequenceNumber: 2n, publishedChildren: p.children };
      });
      vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
        metadata: { version: 'v1' },
      } as never);
      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({} as never);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
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
            name: 'doc.txt',
            originalParentIpnsName: 'source-ipns',
            originalPath: '/old',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            filePointer: existingChild,
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState,
        binCtx,
      });

      // Exactly one listing for f1 — the prior copy was replaced, not duplicated,
      // and it kept its original name (no spurious "(restored)" rename against itself).
      const f1Entries = (publishedChildren ?? []).filter((c) => c.id === 'f1');
      expect(f1Entries).toHaveLength(1);
      expect(f1Entries[0].name).toBe('doc.txt');
    });

    it('aborts before publishing the target folder when the file IPNS key is missing', async () => {
      // Re-encrypt is required (different folder) but impossible (no file IPNS key);
      // the precondition aborts BEFORE the publish so no undecryptable listing is
      // left behind in the target.
      const folderTree = new FolderTree();
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: new Uint8Array(32).fill(0x22),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'doc.txt',
            originalParentIpnsName: 'source-ipns',
            originalPath: '/old',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            originalFolderKeyEncrypted: 'cafe'.repeat(16),
            filePointer: {
              type: 'file',
              id: 'f1',
              name: 'doc.txt',
              fileMetaIpnsName: 'k51f',
              ipnsPrivateKeyEncrypted: '',
              createdAt: 0,
              modifiedAt: 0,
            },
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await expect(
        restoreFromBin({
          entryId: 'e1',
          targetFolderIpnsName: 'target-ipns',
          folderTree,
          binState,
          binCtx,
        })
      ).rejects.toThrow('missing file IPNS key');

      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
    });

    it('throws when restoring a legacy entry (no captured key) to a different folder while the original parent is not loaded', async () => {
      const folderTree = new FolderTree();
      folderTree.set('target-ipns', {
        ipnsName: 'target-ipns',
        folderKey: new Uint8Array(32).fill(0x22),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'doc.txt',
            originalParentIpnsName: 'gone-ipns',
            originalPath: '/old',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            filePointer: {
              type: 'file',
              id: 'f1',
              name: 'doc.txt',
              fileMetaIpnsName: 'k51f',
              ipnsPrivateKeyEncrypted: 'abc',
              createdAt: 0,
              modifiedAt: 0,
            },
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await expect(
        restoreFromBin({
          entryId: 'e1',
          targetFolderIpnsName: 'target-ipns',
          folderTree,
          binState,
          binCtx,
        })
      ).rejects.toThrow('Original parent folder must be loaded');
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
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

    it('unpins content AND every version CID (prior bug: versions were never looped)', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
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
            versionCids: [
              { cid: 'bafyv1', size: 50 },
              { cid: 'bafyv2', size: 40 },
            ],
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await permanentDeleteFromBin({ entryId: 'e1', binState, binCtx });

      const unpinned = vi.mocked(sdkCore.unpinFromIpfs).mock.calls.map((c) => c[1]);
      expect(unpinned).toEqual(['bafycontent', 'bafyv1', 'bafyv2']);
    });

    it('unpins every descendant CID of a deleted folder entry', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 2n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'folder',
            name: 'Sub',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            descendantCids: [
              { cid: 'bafyd1', size: 10 },
              { cid: 'bafyd2', size: 20 },
            ],
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await permanentDeleteFromBin({ entryId: 'e1', binState, binCtx });

      const unpinned = vi.mocked(sdkCore.unpinFromIpfs).mock.calls.map((c) => c[1]);
      expect(unpinned).toEqual(['bafyd1', 'bafyd2']);
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

    it('unpins content + version + descendant CIDs across all entries', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 3n,
      });
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
            versionCids: [{ cid: 'bafyav1', size: 1 }],
          },
          {
            id: 'e2',
            itemType: 'folder',
            name: 'Sub',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            descendantCids: [{ cid: 'bafyd1', size: 2 }],
          },
        ],
        sequenceNumber: 2,
        ipnsName: 'k51bin',
      };

      await emptyBin({ binState, binCtx });

      const unpinned = vi.mocked(sdkCore.unpinFromIpfs).mock.calls.map((c) => c[1]);
      expect(new Set(unpinned)).toEqual(new Set(['bafya', 'bafyav1', 'bafyd1']));
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
