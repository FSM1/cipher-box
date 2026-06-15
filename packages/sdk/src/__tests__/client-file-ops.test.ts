/**
 * Client file-op unit tests — covers replaceFile, restoreFileVersion, and
 * deleteFileVersion. These methods own the full publish + folderTree
 * bookkeeping + folder:updated emission cycle (REQ-1).
 *
 * Each method:
 *  - reads folder + sequence from folderTree.get() at call time,
 *  - captures baseChildren internally,
 *  - publishes via sdk-core (updateFileMetadata + conditional
 *    updateFolderMetadataAndPublish),
 *  - adopts publishedChildren + newSequenceNumber,
 *  - emits folder:updated.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import type { SdkEvent } from '../events';
import type { FileMetadata } from '@cipherbox/core';
import { createTestConfig, setupFolder } from './helpers';

// Mock crypto (clearBytes used elsewhere in client for key cleanup)
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
}));

// Mock sdk-core — override only the publish helpers exercised here
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    updateFileMetadata: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

/** Minimal FileMetadata fixture for the pre-resolved currentMetadata param. */
function makeCurrentMetadata(overrides?: Partial<FileMetadata>): FileMetadata {
  return {
    version: 'v1',
    cid: 'bafyold',
    fileKeyEncrypted: 'oldKey',
    fileIv: 'oldIv',
    size: 100,
    mimeType: 'text/plain',
    encryptionMode: 'GCM',
    createdAt: 1000,
    modifiedAt: 1000,
    ...overrides,
  };
}

/** A published-children fixture with a bumped modifiedAt on the matching file. */
function bumpedChild(modifiedAt: number) {
  return {
    type: 'file' as const,
    id: 'file1',
    name: 'test.txt',
    fileMetaIpnsName: 'k51file',
    ipnsPrivateKeyEncrypted: 'abc',
    createdAt: 0,
    modifiedAt,
  };
}

describe('CipherBoxClient - file ops', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('replaceFile', () => {
    it('publishes file + folder, adopts publishedChildren, emits folder:updated, returns prunedCids', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: 'k51file',
        metadataCid: 'bafymetanew',
        newSequenceNumber: 2n,
        prunedCids: ['cidP'],
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafyfolder',
        newSequenceNumber: 3n,
        publishedChildren: [bumpedChild(999)],
      });

      const fileIpnsPrivateKey = new Uint8Array(64).fill(7);
      const result = await client.replaceFile('folder-ipns', 'file1', {
        fileIpnsPrivateKey,
        currentMetadata: makeCurrentMetadata(),
        updates: { cid: 'bafynewcontent', fileKeyEncrypted: 'newKey', fileIv: 'newIv', size: 200 },
        createVersion: true,
      });

      // Both publishes ran
      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);

      // updateFileMetadata received the pre-resolved key + metadata + updates
      expect(sdkCore.updateFileMetadata).toHaveBeenCalledWith(
        expect.objectContaining({
          fileIpnsPrivateKey,
          fileMetaIpnsName: 'k51file',
          createVersion: true,
          updates: expect.objectContaining({ cid: 'bafynewcontent' }),
        })
      );

      // folder publish carried the pre-mutation baseChildren snapshot
      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledWith(
        expect.objectContaining({
          ipnsName: 'folder-ipns',
          sequenceNumber: 1n,
          baseChildren: expect.any(Array),
        })
      );

      // prunedCids returned to the caller for unpin
      expect(result.prunedCids).toEqual(['cidP']);

      // folderTree advanced to the folder publish's new sequence + adopted children
      const folder = client.getFolderTree().get('folder-ipns');
      expect(folder?.sequenceNumber).toBe(3n);
      expect(folder?.children).toEqual([bumpedChild(999)]);

      // folder:updated emitted with publishedChildren + sequenceNumber 3n
      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated).toBeDefined();
      expect(updated?.ipnsName).toBe('folder-ipns');
      expect(updated?.sequenceNumber).toBe(3n);
      expect(updated?.children).toEqual([bumpedChild(999)]);
    });

    it('throws when the parent folder is not loaded', async () => {
      await expect(
        client.replaceFile('absent-ipns', 'file1', {
          fileIpnsPrivateKey: new Uint8Array(64),
          currentMetadata: makeCurrentMetadata(),
          updates: { cid: 'x' },
          createVersion: false,
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });

  describe('restoreFileVersion', () => {
    it('publishes file only (no migration), keeps folder sequence, emits folder:updated, returns prunedCids', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: 'k51file',
        metadataCid: 'bafyrestored',
        newSequenceNumber: 4n,
        prunedCids: ['cidPruned'],
      });

      const result = await client.restoreFileVersion('folder-ipns', 'file1', 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(9),
        currentMetadata: makeCurrentMetadata(),
        updates: { cid: 'bafyrestored', fileKeyEncrypted: 'rk', fileIv: 'riv', size: 50 },
      });

      // File publish ran; folder publish did NOT (no key migration)
      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();

      // prunedCids surfaced
      expect(result.prunedCids).toEqual(['cidPruned']);

      // folder sequence unchanged (file-only publish does not advance the folder)
      const folder = client.getFolderTree().get('folder-ipns');
      expect(folder?.sequenceNumber).toBe(1n);

      // folder:updated still emitted with the current folderTree snapshot
      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated).toBeDefined();
      expect(updated?.sequenceNumber).toBe(1n);
      expect(updated?.children).toEqual(folder?.children);
    });

    it('does a conditional folder publish on key migration and advances the folder sequence', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: 'k51file',
        metadataCid: 'bafyrestored',
        newSequenceNumber: 4n,
        prunedCids: [],
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafyfolder',
        newSequenceNumber: 5n,
        publishedChildren: [bumpedChild(1234)],
      });

      await client.restoreFileVersion('folder-ipns', 'file1', 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(9),
        currentMetadata: makeCurrentMetadata(),
        updates: { cid: 'bafyrestored' },
        migratedIpnsPrivateKeyEncrypted: 'migrated-hex',
      });

      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);

      const folder = client.getFolderTree().get('folder-ipns');
      expect(folder?.sequenceNumber).toBe(5n);
      expect(folder?.children).toEqual([bumpedChild(1234)]);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated?.sequenceNumber).toBe(5n);
      expect(updated?.children).toEqual([bumpedChild(1234)]);
    });

    it('throws when the parent folder is not loaded', async () => {
      await expect(
        client.restoreFileVersion('absent-ipns', 'file1', 0, {
          fileIpnsPrivateKey: new Uint8Array(64),
          currentMetadata: makeCurrentMetadata(),
          updates: { cid: 'x' },
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });

  describe('deleteFileVersion', () => {
    it('publishes file only (no migration), keeps folder sequence, emits folder:updated, returns deletedCid', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: 'k51file',
        metadataCid: 'bafyafterdelete',
        newSequenceNumber: 6n,
        prunedCids: [],
      });

      const result = await client.deleteFileVersion('folder-ipns', 'file1', 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(3),
        currentMetadata: makeCurrentMetadata(),
        updates: { cid: 'bafyold' },
        deletedCid: 'cidDeleted',
      });

      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();

      expect(result.deletedCid).toBe('cidDeleted');

      const folder = client.getFolderTree().get('folder-ipns');
      expect(folder?.sequenceNumber).toBe(1n);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated).toBeDefined();
      expect(updated?.sequenceNumber).toBe(1n);
      expect(updated?.children).toEqual(folder?.children);
    });

    it('returns prunedCids from a conflict-merge round for the caller to unpin', async () => {
      setupFolder(client);

      // A 409-conflict merge inside updateFileMetadata can re-add versions past the
      // cap; deleteFileVersion must surface those CIDs so the web tier unpins them.
      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: 'k51file',
        metadataCid: 'bafyafterdelete',
        newSequenceNumber: 6n,
        prunedCids: ['cidMergePruned1', 'cidMergePruned2'],
      });

      const result = await client.deleteFileVersion('folder-ipns', 'file1', 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(3),
        currentMetadata: makeCurrentMetadata(),
        updates: { cid: 'bafyold' },
        deletedCid: 'cidDeleted',
      });

      expect(result.deletedCid).toBe('cidDeleted');
      expect(result.prunedCids).toEqual(['cidMergePruned1', 'cidMergePruned2']);
    });

    it('does a conditional folder publish on key migration and advances the folder sequence', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: 'k51file',
        metadataCid: 'bafyafterdelete',
        newSequenceNumber: 6n,
        prunedCids: [],
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafyfolder',
        newSequenceNumber: 7n,
        publishedChildren: [bumpedChild(4321)],
      });

      await client.deleteFileVersion('folder-ipns', 'file1', 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(3),
        currentMetadata: makeCurrentMetadata(),
        updates: { cid: 'bafyold' },
        deletedCid: 'cidDeleted',
        migratedIpnsPrivateKeyEncrypted: 'migrated-hex',
      });

      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);

      const folder = client.getFolderTree().get('folder-ipns');
      expect(folder?.sequenceNumber).toBe(7n);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated?.sequenceNumber).toBe(7n);
      expect(updated?.children).toEqual([bumpedChild(4321)]);
    });

    it('throws when the parent folder is not loaded', async () => {
      await expect(
        client.deleteFileVersion('absent-ipns', 'file1', 0, {
          fileIpnsPrivateKey: new Uint8Array(64),
          currentMetadata: makeCurrentMetadata(),
          updates: { cid: 'x' },
          deletedCid: 'c',
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });
});
