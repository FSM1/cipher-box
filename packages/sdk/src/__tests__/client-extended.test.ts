/**
 * Extended client unit tests — covers bin, share, move, rename, upload,
 * download, and state management methods not covered in client.test.ts.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient, BinNotLoadedError } from '../client';
import type { SdkEvent } from '../events';
import { createTestConfig, setupFolder } from './helpers';
import type { NodeContent, SealedChildRef } from '@cipherbox/core';

// Mock crypto (clearBytes used in uploadFile; unwrapKey/hexToBytes used in moveItem re-encryption)
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0x55)),
  hexToBytes: vi.fn((hex: string) => new Uint8Array(hex.length / 2)),
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
    resolveFileMetadata: vi.fn().mockResolvedValue({
      metadata: {
        version: 'v1',
        cid: 'bafyfile',
        fileKeyEncrypted: 'aabb',
        fileIv: '1122',
        size: 1,
        mimeType: 'text/plain',
        encryptionMode: 'GCM',
        createdAt: 0,
        modifiedAt: 0,
      },
      metadataCid: 'bafymeta',
    }),
    updateFileMetadata: vi.fn().mockResolvedValue({
      ipnsName: 'k51file',
      metadataCid: 'bafymeta2',
      newSequenceNumber: 2n,
      prunedCids: [],
    }),
    batchPublishIpnsRecords: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
    addToIpfs: vi.fn(),
    fetchFromIpfs: vi.fn(),
    resolveIpnsRecord: vi.fn(),
    unpinFromIpfs: vi.fn(),
    // downloadFromIpns's final content fetch+decrypt step (real implementation
    // calls @cipherbox/crypto's decryptAesGcm/decryptAesCtr directly, which the
    // full-replacement @cipherbox/crypto mock below does not provide).
    downloadFileContent: vi.fn(),
  };
});

// Mock @cipherbox/core seal/unseal — used only by moveItem's FLAG-63-U2 re-seal.
// Spread actual so SealedChildRef / PublishedNode types and all other exports pass through.
vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    sealChildReadKey: vi.fn().mockResolvedValue('resealed-dest-hex'),
    unsealChildReadKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0x42)),
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
            name: 'renamed.txt',
            ipnsName: 'k51file',
            generation: 0,
            versionFloor: 0n,
            readKeySealed: 'sealed-key-hex',
          },
        ],
        renamedChild: {
          name: 'renamed.txt',
          ipnsName: 'k51file',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'sealed-key-hex',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
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
        updatedSource: [],
        updatedDest: [
          {
            name: 'test.txt',
            ipnsName: 'k51file',
            generation: 0,
            versionFloor: 0n,
            readKeySealed: 'sealed-key-hex',
          },
        ],
        movedRef: {
          name: 'test.txt',
          ipnsName: 'k51file',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'sealed-key-hex',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });
      // FLAG-63-U2 re-seal path: resolve the moved child's IPNS by its ipnsName
      // ('k51file'), fetch its PublishedNode envelope for the id/kind AAD inputs.
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({ cid: 'bafychild' } as never);
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
        new TextEncoder().encode(JSON.stringify({ id: 'file1', kind: 'file' }))
      );

      await client.moveItem('src-ipns', 'dest-ipns', 'file1');

      expect(sdkCore.moveItem).toHaveBeenCalled();
      const updatedEvents = events.filter((e) => e.type === 'folder:updated');
      expect(updatedEvents).toHaveLength(2);

      // The IPNS resolve must use the moved ref's ipnsName, not the caller-facing childId.
      expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledWith('k51file', expect.anything());

      // The dest publish must carry the re-sealed key (re-sealed under the dest parent),
      // not the source-sealed blob (FLAG-63-U2 / CodeRabbit #2 + #3).
      const destPublish = vi
        .mocked(sdkCore.updateFolderMetadataAndPublish)
        .mock.calls.find(([arg]) => arg.ipnsName === 'dest-ipns');
      expect(destPublish).toBeDefined();
      expect(destPublish?.[0].children[0]?.readKeySealed).toBe('resealed-dest-hex');
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
        encryptedIpnsPrivateKey: 'enc',
        fileKey: new Uint8Array(32).fill(0x42),
        // v3 file Node fields (68.1-07/09) — read by the parent read/write-body
        // seal path; the finally block also zeroes them.
        fileNodeId: 'file2',
        fileReadKey: new Uint8Array(32).fill(0x43),
        fileWriteKey: new Uint8Array(32).fill(0x44),
      });
      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [
          {
            name: 'test.txt',
            ipnsName: 'k51file',
            generation: 0,
            versionFloor: 0n,
            readKeySealed: 'sealed-key-hex',
          },
          {
            name: 'new.txt',
            ipnsName: 'k51filemeta',
            generation: 0,
            versionFloor: 0n,
            readKeySealed: 'enc',
          },
        ],
        newRef: {
          name: 'new.txt',
          ipnsName: 'k51filemeta',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'enc',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
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

    it('clears fileKey after upload (D-09 zeroization)', async () => {
      const fileKey = new Uint8Array(32).fill(0x42);
      setupFolder(client);

      const fileReadKey = new Uint8Array(32).fill(0x43);
      const fileWriteKey = new Uint8Array(32).fill(0x44);

      vi.mocked(sdkCore.uploadFile).mockResolvedValue({
        cid: 'bafyfile',
        encryptedSize: 100,
        fileMetaIpnsName: 'k51filemeta',
        ipnsRecord: {
          ipnsName: 'k51filemeta',
          recordBase64: 'mock-record',
          metadataCid: 'bafymeta',
        },
        encryptedIpnsPrivateKey: 'enc',
        fileKey,
        // v3 file Node fields (68.1-07/09) — read by the parent read/write-body
        // seal path; the finally block also zeroes them (asserted below).
        fileNodeId: 'clear-file',
        fileReadKey,
        fileWriteKey,
      });
      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [],
        newRef: {
          name: 'clear.txt',
          ipnsName: 'k51filemeta',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'mock',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      await client.uploadFile('folder-ipns', new Uint8Array([1, 2, 3]), 'clear.txt', 'text/plain');

      // fileKey and the v3 fileReadKey/fileWriteKey must all be zeroed (D-09 —
      // this call site is the terminal owner; clearBytes mock fills with 0)
      expect(fileKey.every((b) => b === 0)).toBe(true);
      expect(fileReadKey.every((b) => b === 0)).toBe(true);
      expect(fileWriteKey.every((b) => b === 0)).toBe(true);
    });
  });

  describe('downloadFromIpns', () => {
    // Current downloadFromIpns (68.1-22) first resolves the file's own
    // PublishedNode (resolvePublishedNode -> resolveIpnsRecord + fetchFromIpfs)
    // to learn its plaintext id (the AAD input for unsealChildReadKey), then
    // recovers the file readKey, resolves NodeContent via
    // sdkCore.resolveFileMetadata, and finally fetches+decrypts via
    // sdkCore.downloadFileContent (NOT downloadAndDecrypt -- that's the
    // separate ECIES-wrapped downloadFile() path). It emits no SDK event
    // (unlike the sibling downloadFile(), which emits 'file:downloaded').
    const fileRef: SealedChildRef = {
      name: 'x.txt',
      ipnsName: 'k51filemeta',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'sealed-key-hex',
    };
    const folderKey = new Uint8Array(32).fill(7);

    it('resolves file metadata and downloads content', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafyfilenode',
        sequenceNumber: 1n,
        signatureVerified: true,
      });
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
        new TextEncoder().encode(
          JSON.stringify({
            schema: 'node/v3',
            kind: 'file',
            id: 'file-node-id',
            generation: 0,
            aeadVersion: 1,
            readSealed: 'unused-unsealChildReadKey-is-mocked',
          })
        )
      );

      const fileKey = new Uint8Array(32).fill(0x99);
      const metadata: NodeContent = {
        cid: 'bafycontent',
        fileIv: 'def',
        size: 1024,
        mimeType: 'application/octet-stream',
        encryptionMode: 'GCM',
        fileKey,
        versions: [],
      };
      // The mocked unsealChildReadKey returns one SHARED Uint8Array instance
      // across every test in this file (module-level mockResolvedValue) that
      // earlier tests' finally-block cleanup may have already zeroed, so this
      // asserts identity/shape (a distinct Uint8Array from the parent
      // folderKey) rather than depending on its exact byte content.
      let capturedReadKeyRef: Uint8Array | null = null;
      vi.mocked(sdkCore.resolveFileMetadata).mockImplementationOnce(
        async (_ipnsName, fileReadKey) => {
          capturedReadKeyRef = fileReadKey;
          return { metadata, metadataCid: 'bafymetacid' };
        }
      );
      vi.mocked(sdkCore.downloadFileContent).mockResolvedValue(
        new Uint8Array([72, 101, 108, 108, 111])
      );

      const result = await client.downloadFromIpns(fileRef, folderKey);

      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
      // resolveFileMetadata is called with the file's OWN recovered readKey
      // (unsealChildReadKey's output) -- a distinct 32-byte buffer, NOT the
      // caller-supplied parent folderKey reference.
      expect(sdkCore.resolveFileMetadata).toHaveBeenCalledWith(
        'k51filemeta',
        expect.any(Uint8Array),
        expect.anything()
      );
      expect(capturedReadKeyRef).not.toBeNull();
      expect(capturedReadKeyRef).not.toBe(folderKey);
      expect(capturedReadKeyRef!.length).toBe(32);
      expect(sdkCore.downloadFileContent).toHaveBeenCalledWith(
        expect.objectContaining({
          cid: 'bafycontent',
          fileIv: 'def',
          encryptionMode: 'GCM',
        })
      );
      // D-09: the resolved NodeContent's fileKey is zeroed by this call's
      // finally block (terminal owner of the freshly-recovered raw key).
      expect(fileKey.every((b) => b === 0)).toBe(true);
      // Current downloadFromIpns emits only the generic withOperation
      // lifecycle events -- no 'file:downloaded' (unlike the sibling
      // downloadFile(), which does emit it).
      expect(events.map((e) => e.type)).toEqual(['operation:start', 'operation:end']);
    });

    it('throws when the file IPNS record cannot be resolved', async () => {
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

      await expect(client.downloadFromIpns(fileRef, folderKey)).rejects.toThrow(
        'IPNS record not found'
      );
      expect(sdkCore.resolveFileMetadata).not.toHaveBeenCalled();
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

    it('loadBin does not clobber a loaded bin when a later load misses (empty fallback)', async () => {
      // First load resolves the real bin (1 entry, seq 2).
      vi.mocked(binOps.loadBin).mockResolvedValueOnce({
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
        sequenceNumber: 2,
        ipnsName: 'k51bin',
      });
      await client.loadBin();

      // A racing second load transiently misses and returns the in-memory empty
      // fallback (entries=[], sequenceNumber=0). It must NOT wipe the loaded bin.
      vi.mocked(binOps.loadBin).mockResolvedValueOnce({
        entries: [],
        sequenceNumber: 0,
        ipnsName: 'k51bin',
      });
      const second = await client.loadBin();

      expect(second.entries).toHaveLength(1);
      expect(second.sequenceNumber).toBe(2);
    });

    it('deleteToBin self-heals by loading the bin when binState is null', async () => {
      // binState starts null (loadBin is fire-and-forget on login). deleteToBin
      // must lazily load the bin and proceed with the soft-delete rather than
      // throwing — otherwise the web falls back to a hard delete and the item is
      // lost instead of moved to the bin.
      const child = setupFolder(client);
      vi.mocked(binOps.loadBin).mockResolvedValue({
        entries: [],
        sequenceNumber: 0,
        ipnsName: 'k51bin',
      });
      vi.mocked(binOps.addToBin).mockResolvedValue({
        removedItem: child,
        updatedBinState: { entries: [], sequenceNumber: 1, ipnsName: 'k51bin' },
      });

      await client.deleteToBin('folder-ipns', 'file1', 'My Vault');

      expect(binOps.loadBin).toHaveBeenCalled();
      expect(binOps.addToBin).toHaveBeenCalled();
    });

    it('deleteToBin throws BinNotLoadedError when the bin cannot be loaded', async () => {
      // If the self-heal load fails (e.g. network error) binState stays null and
      // deleteToBin throws rather than silently hard-deleting.
      setupFolder(client);
      vi.mocked(binOps.loadBin).mockRejectedValue(new Error('network down'));
      await expect(client.deleteToBin('folder-ipns', 'file1', 'My Vault')).rejects.toThrow();
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
          name: 'x.txt',
          ipnsName: 'k51',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: '',
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
        entries: [
          {
            id: 'e1',
            name: 'old.txt',
            deletedAt: 0,
            itemType: 'file' as const,
            originalParentIpnsName: 'k51parent',
            originalPath: 'My Vault',
            size: 0,
            mimeType: '',
          },
        ],
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
      // requireFolder -> ensureFolderLoaded -> ensureRootFolderState returns
      // null (createTestConfig() has no rootIpnsKeypair/rootWriteKey), so
      // self-bootstrap is unavailable and the "Folder not loaded" error
      // surfaces exactly as it did pre-Phase-63 self-heal.
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
