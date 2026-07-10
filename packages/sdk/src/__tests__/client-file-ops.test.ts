/**
 * Client file-op unit tests — covers replaceFile, restoreFileVersion, and
 * deleteFileVersion. These methods own the full publish + folderTree
 * bookkeeping + folder:updated emission cycle (REQ-1) via the shared
 * `runFileVersionOp` core (72-10 SC#6).
 *
 * The pre-68.1-09 version of this suite fixtured a legacy `FileMetadata`
 * shape (`version`/`fileKeyEncrypted`, no per-file Node) and asserted the
 * three methods ALWAYS republish the parent folder. Both premises are stale:
 *
 *   - `currentMetadata`/`updates` are now typed `NodeContent` /
 *     `sdkCore.UpdateFileContentParams` (68.1-09) -- the file's own read/write
 *     keys are resolved from the PARENT's write-chain
 *     (`resolveFileWriteChainKeys`: `WriteChildRef` sealed under the parent
 *     writeKey), not supplied as a bare `fileIpnsPrivateKey` the caller
 *     unwrapped independently.
 *   - The parent folder is republished ONLY when the caller supplies
 *     `migratedIpnsPrivateKeyEncrypted` (a lazy TEE-key-epoch migration
 *     piggybacked on the file mutation, `maybeRepublishFolderForFileMigration`)
 *     -- a plain content/version edit is a FILE-ONLY publish that leaves the
 *     folder's own IPNS sequence untouched (SealedChildRef carries no
 *     size/modifiedAt to bump, NODE-03). `folder:updated` is still emitted
 *     from the current folderTree snapshot either way.
 *
 * Only the network-touching sdk-core seams (`resolveIpnsRecord`,
 * `fetchFromIpfs`) and the two publish calls (`updateFileMetadata`,
 * `updateFolderMetadataAndPublish`) are mocked -- every `@cipherbox/core`
 * seal/unseal primitive stays real (mirrors delete-item.test.ts /
 * client-write-descriptor.test.ts's 68.1-18 fixture pattern).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import type { SdkEvent } from '../events';
import type { FolderState } from '../types';
import { createTestConfig } from './helpers';
import {
  sealNode,
  sealChildReadKey,
  sealChildWriteKey,
  type Node,
  type NodeContent,
  type SealedChildRef,
  type WriteChildRef,
} from '@cipherbox/core';
import type { UpdateFileContentParams } from '@cipherbox/sdk-core';

vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  };
});

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    updateFileMetadata: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const FOLDER_IPNS = 'k51folder';
const FILE_IPNS = 'k51file';
const FILE_NODE_ID = '11111111-1111-4111-8111-111111111111';
const GEN = 0;

const folderKey = new Uint8Array(32).fill(0x11);
const writeKey = new Uint8Array(32).fill(0x22);
const fileReadKey = new Uint8Array(32).fill(0x33);
const fileWriteKey = new Uint8Array(32).fill(0x44);

/** Minimal valid NodeContent (replaces the retired FileMetadata shape). */
function makeCurrentMetadata(overrides?: Partial<NodeContent>): NodeContent {
  return {
    cid: 'bafyold',
    fileIv: 'b2xkSXY=',
    size: 100,
    mimeType: 'text/plain',
    encryptionMode: 'GCM',
    fileKey: new Uint8Array(32).fill(0x55),
    versions: [],
    ...overrides,
  };
}

function makeUpdates(overrides?: Partial<UpdateFileContentParams>): UpdateFileContentParams {
  return {
    cid: 'bafynewcontent',
    fileKey: new Uint8Array(32).fill(0x66),
    fileIv: new Uint8Array(12).fill(0x77),
    size: 200,
    mimeType: 'text/plain',
    encryptionMode: 'GCM',
    ...overrides,
  };
}

/**
 * Seed a write-capable parent FolderState carrying a real WriteChildRef +
 * SealedChildRef for FILE_NODE_ID, and mock the network so
 * `resolveFileWriteChainKeys` (private, exercised for real) can recover the
 * file's read/write keys and its own PublishedNode's id/generation/createdAt.
 */
async function seedFile(client: CipherBoxClient): Promise<{ fileIpnsPrivateKey: Uint8Array }> {
  const fileSealedRef: SealedChildRef = {
    name: 'test.txt',
    ipnsName: FILE_IPNS,
    generation: GEN,
    versionFloor: 1n,
    readKeySealed: await sealChildReadKey(fileReadKey, folderKey, FILE_NODE_ID, 'file', GEN),
  };
  const writeChildRef: WriteChildRef = {
    childId: FILE_NODE_ID,
    writeKeySealed: await sealChildWriteKey(fileWriteKey, writeKey, FILE_NODE_ID, 'file', GEN),
  };

  const state: FolderState = {
    ipnsName: FOLDER_IPNS,
    folderKey,
    writeKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [fileSealedRef],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'folder-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [fileSealedRef],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(3), writeChildren: [writeChildRef] },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'folder-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(FOLDER_IPNS, state);

  const fileOwnIpnsPrivateKey = new Uint8Array(64).fill(9);
  const fileNode: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: FILE_NODE_ID,
    generation: GEN,
    createdAt: 1000,
    modifiedAt: 1000,
    content: makeCurrentMetadata(),
    writeBody: { ipnsPrivateKey: fileOwnIpnsPrivateKey, writeChildren: [] },
  };
  const publishedFile = await sealNode(fileNode, fileReadKey, fileWriteKey);

  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === FILE_IPNS) {
      return { cid: 'bafychild', sequenceNumber: 1n, signatureVerified: true };
    }
    return null;
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
    if (cid === 'bafychild') {
      return new TextEncoder().encode(JSON.stringify(publishedFile));
    }
    throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
  });

  return { fileIpnsPrivateKey: fileOwnIpnsPrivateKey };
}

describe('CipherBoxClient - file ops', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('replaceFile', () => {
    it('publishes the file only (no migration key): folder sequence untouched, folder:updated still emitted, prunedCids surfaced', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      await seedFile(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: FILE_IPNS,
        metadataCid: 'bafymetanew',
        newSequenceNumber: 2n,
        prunedCids: ['cidP'],
      });

      const callerFileIpnsPrivateKey = new Uint8Array(64).fill(7);
      const updates = makeUpdates();
      const result = await client.replaceFile(FOLDER_IPNS, FILE_IPNS, {
        fileIpnsPrivateKey: callerFileIpnsPrivateKey,
        currentMetadata: makeCurrentMetadata(),
        updates,
        createVersion: true,
      });

      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      // No migration key supplied -> no folder republish.
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();

      expect(sdkCore.updateFileMetadata).toHaveBeenCalledWith(
        expect.objectContaining({
          fileIpnsPrivateKey: callerFileIpnsPrivateKey,
          fileReadKey: expect.any(Uint8Array),
          fileWriteKey: expect.any(Uint8Array),
          fileMetaIpnsName: FILE_IPNS,
          fileSequenceNumber: 1n,
          nodeId: FILE_NODE_ID,
          nodeGeneration: GEN,
          originalCreatedAt: 1000,
          createVersion: true,
          updates: expect.objectContaining({ cid: 'bafynewcontent' }),
        })
      );

      expect(result.prunedCids).toEqual(['cidP']);

      // Folder sequence/children untouched -- a file-only publish never
      // advances the parent's own IPNS sequence.
      const folder = client.getFolderTree().get(FOLDER_IPNS);
      expect(folder?.sequenceNumber).toBe(1n);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated).toBeDefined();
      expect(updated?.ipnsName).toBe(FOLDER_IPNS);
      expect(updated?.sequenceNumber).toBe(1n);
    });

    it('throws when the parent folder is not loaded', async () => {
      await expect(
        client.replaceFile('absent-ipns', FILE_IPNS, {
          fileIpnsPrivateKey: new Uint8Array(64),
          currentMetadata: makeCurrentMetadata(),
          updates: makeUpdates(),
          createVersion: false,
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });

  describe('restoreFileVersion', () => {
    it('publishes the file only (no migration key), keeps folder sequence, emits folder:updated, returns prunedCids', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      await seedFile(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: FILE_IPNS,
        metadataCid: 'bafyrestored',
        newSequenceNumber: 4n,
        prunedCids: ['cidPruned'],
      });

      const result = await client.restoreFileVersion(FOLDER_IPNS, FILE_IPNS, 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(9),
        currentMetadata: makeCurrentMetadata(),
        updates: makeUpdates({ cid: 'bafyrestored' }),
      });

      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      expect(sdkCore.updateFileMetadata).toHaveBeenCalledWith(
        expect.objectContaining({ createVersion: false })
      );
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();

      expect(result.prunedCids).toEqual(['cidPruned']);

      const folder = client.getFolderTree().get(FOLDER_IPNS);
      expect(folder?.sequenceNumber).toBe(1n);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated).toBeDefined();
      expect(updated?.sequenceNumber).toBe(1n);
    });

    it('does a conditional folder publish on key migration and advances the folder sequence', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      await seedFile(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: FILE_IPNS,
        metadataCid: 'bafyrestored',
        newSequenceNumber: 4n,
        prunedCids: [],
      });
      const migratedChild: SealedChildRef = {
        name: 'test.txt',
        ipnsName: FILE_IPNS,
        generation: GEN,
        versionFloor: 1n,
        readKeySealed: 'unused-in-this-assertion',
      };
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafyfolder',
        newSequenceNumber: 5n,
        publishedChildren: [migratedChild],
      });

      await client.restoreFileVersion(FOLDER_IPNS, FILE_IPNS, 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(9),
        currentMetadata: makeCurrentMetadata(),
        updates: makeUpdates({ cid: 'bafyrestored' }),
        migratedIpnsPrivateKeyEncrypted: 'migrated-hex',
      });

      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledWith(
        expect.objectContaining({ encryptedIpnsPrivateKey: 'migrated-hex' })
      );

      const folder = client.getFolderTree().get(FOLDER_IPNS);
      expect(folder?.sequenceNumber).toBe(5n);
      expect(folder?.children).toEqual([migratedChild]);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated?.sequenceNumber).toBe(5n);
    });

    it('throws when the parent folder is not loaded', async () => {
      await expect(
        client.restoreFileVersion('absent-ipns', FILE_IPNS, 0, {
          fileIpnsPrivateKey: new Uint8Array(64),
          currentMetadata: makeCurrentMetadata(),
          updates: makeUpdates(),
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });

  describe('deleteFileVersion', () => {
    it('publishes the file only (no migration key), keeps folder sequence, emits folder:updated, returns deletedCid', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      await seedFile(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: FILE_IPNS,
        metadataCid: 'bafyafterdelete',
        newSequenceNumber: 6n,
        prunedCids: [],
      });

      const result = await client.deleteFileVersion(FOLDER_IPNS, FILE_IPNS, 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(3),
        currentMetadata: makeCurrentMetadata(),
        updates: makeUpdates({ cid: 'bafyold' }),
        deletedCid: 'cidDeleted',
      });

      expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
      expect(sdkCore.updateFileMetadata).toHaveBeenCalledWith(
        expect.objectContaining({ createVersion: false })
      );
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();

      expect(result.deletedCid).toBe('cidDeleted');
      expect(result.prunedCids).toEqual([]);

      const folder = client.getFolderTree().get(FOLDER_IPNS);
      expect(folder?.sequenceNumber).toBe(1n);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated).toBeDefined();
      expect(updated?.sequenceNumber).toBe(1n);
    });

    it('returns prunedCids from a conflict-merge round for the caller to unpin', async () => {
      await seedFile(client);

      // A 409-conflict merge inside updateFileMetadata can re-add versions past
      // the cap; deleteFileVersion must surface those CIDs so the web tier
      // unpins them.
      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: FILE_IPNS,
        metadataCid: 'bafyafterdelete',
        newSequenceNumber: 6n,
        prunedCids: ['cidMergePruned1', 'cidMergePruned2'],
      });

      const result = await client.deleteFileVersion(FOLDER_IPNS, FILE_IPNS, 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(3),
        currentMetadata: makeCurrentMetadata(),
        updates: makeUpdates({ cid: 'bafyold' }),
        deletedCid: 'cidDeleted',
      });

      expect(result.deletedCid).toBe('cidDeleted');
      expect(result.prunedCids).toEqual(['cidMergePruned1', 'cidMergePruned2']);
    });

    it('does a conditional folder publish on key migration and advances the folder sequence', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      await seedFile(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: FILE_IPNS,
        metadataCid: 'bafyafterdelete',
        newSequenceNumber: 6n,
        prunedCids: [],
      });
      const migratedChild: SealedChildRef = {
        name: 'test.txt',
        ipnsName: FILE_IPNS,
        generation: GEN,
        versionFloor: 1n,
        readKeySealed: 'unused-in-this-assertion',
      };
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafyfolder',
        newSequenceNumber: 7n,
        publishedChildren: [migratedChild],
      });

      await client.deleteFileVersion(FOLDER_IPNS, FILE_IPNS, 0, {
        fileIpnsPrivateKey: new Uint8Array(64).fill(3),
        currentMetadata: makeCurrentMetadata(),
        updates: makeUpdates({ cid: 'bafyold' }),
        deletedCid: 'cidDeleted',
        migratedIpnsPrivateKeyEncrypted: 'migrated-hex',
      });

      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);

      const folder = client.getFolderTree().get(FOLDER_IPNS);
      expect(folder?.sequenceNumber).toBe(7n);

      const updated = events.find(
        (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
      );
      expect(updated?.sequenceNumber).toBe(7n);
    });

    it('throws when the parent folder is not loaded', async () => {
      await expect(
        client.deleteFileVersion('absent-ipns', FILE_IPNS, 0, {
          fileIpnsPrivateKey: new Uint8Array(64),
          currentMetadata: makeCurrentMetadata(),
          updates: makeUpdates(),
          deletedCid: 'c',
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });
});
