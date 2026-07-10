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
import type { NodeContent, SealedChildRef } from '@cipherbox/core';

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
}));

import * as sdkCore from '@cipherbox/sdk-core';
import { unwrapKey } from '@cipherbox/crypto';

// ── helpers ────────────────────────────────────────────────────────────────────

const SRC_IPNS = 'k51src';
const DEST_IPNS = 'k51dest';
const FILE_ID = 'file-uuid-1';
const FILE_META_IPNS = 'k51filemeta';

const SRC_FOLDER_KEY = new Uint8Array(32).fill(0x11);
const DEST_FOLDER_KEY = new Uint8Array(32).fill(0x22);

/** Populate the client's folderTree with src and dest folders. */
function setupFolders(client: CipherBoxClient) {
  const now = Date.now();
  // 68.2: SealedChildRef's field set is FROZEN to exactly {name, ipnsName,
  // generation, versionFloor, readKeySealed} — no `id`/`fileMetaIpnsName`/
  // `ipnsPrivateKeyEncrypted` (those were legacy FilePointer fields). `ipnsName`
  // now IS the identity used to locate the child (mirrors moveItem's real
  // childId === ref.ipnsName match in sdk-core/folder/metadata-ops.ts).
  const filePointer: SealedChildRef = {
    name: 'hello.txt',
    ipnsName: FILE_ID,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: 'sealed-file-readkey',
  };

  client.getFolderTree().set(SRC_IPNS, {
    ipnsName: SRC_IPNS,
    folderKey: new Uint8Array(SRC_FOLDER_KEY),
    writeKey: new Uint8Array(32).fill(0x33),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0xaa),
      privateKey: new Uint8Array(64).fill(0xbb),
    },
    sequenceNumber: 1n,
    children: [filePointer],
    metadata: null,
    lastLoadedAt: now,
    nodeId: 'src-node-id',
    nodeGeneration: 0,
  });

  client.getFolderTree().set(DEST_IPNS, {
    ipnsName: DEST_IPNS,
    folderKey: new Uint8Array(DEST_FOLDER_KEY),
    writeKey: new Uint8Array(32).fill(0x44),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0xcc),
      privateKey: new Uint8Array(64).fill(0xdd),
    },
    sequenceNumber: 1n,
    children: [],
    metadata: null,
    lastLoadedAt: now,
    nodeId: 'dest-node-id',
    nodeGeneration: 0,
  });
}

/** Minimal valid NodeContent (replaces the retired FileMetadata shape). */
const mockFileMeta: NodeContent = {
  cid: 'bafyfile',
  fileIv: '112233',
  size: 42,
  mimeType: 'text/plain',
  encryptionMode: 'GCM',
  fileKey: new Uint8Array(32).fill(0x77),
  versions: [],
};

// ── tests ──────────────────────────────────────────────────────────────────────

describe.skip('CipherBoxClient.moveItem — file metadata re-encryption — TODO(phase 65)', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
    setupFolders(client);

    // sdkCore.moveItem returns the shuffled children arrays. Real return shape
    // is { updatedSource, updatedDest, movedRef } (sdk-core/folder/metadata-ops.ts)
    // — NOT updatedSourceChildren/updatedDestChildren/movedItem.
    const movedFileRef: SealedChildRef = {
      name: 'hello.txt',
      ipnsName: FILE_ID,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'sealed-file-readkey',
    };
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [movedFileRef],
      movedRef: movedFileRef,
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
    // 68.2: updateFileMetadata's params no longer carry a folder-scoped key at
    // all — the per-file Node (Phase 68.1-07) is sealed under its OWN
    // fileReadKey/fileWriteKey, independent of any parent folder key (there is
    // no `folderKey` field on this type any more). The re-encrypt-under-the-
    // destination-folder-key premise this suite was written against is
    // superseded: the current `moveItem` (sdk-core/folder/metadata-ops.ts) is a
    // pure SealedChildRef link rewrite with ZERO re-encryption (READ-04), so
    // this whole describe block is retired pending a phase-65 rewrite (see the
    // describe.skip title). Mapped onto the closest surviving field so this
    // dead code still typechecks against the current signature.
    expect(params.fileWriteKey).toEqual(DEST_FOLDER_KEY);
    // Must not create a new version (re-encryption is not a content change)
    expect(params.createVersion).toBe(false);
    // Must carry the same content unchanged
    expect(params.updates).toEqual({});
    // Must use the correct IPNS name
    expect(params.fileMetaIpnsName).toBe(FILE_META_IPNS);
  });

  it('does NOT re-encrypt file metadata when moving a folder (no FilePointer involved)', async () => {
    const folderChild: SealedChildRef = {
      name: 'SubDir',
      ipnsName: 'k51subfolder',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'sealed-folder-readkey',
    };

    // Replace file with folder child in source
    const srcState = client.getFolderTree().get(SRC_IPNS)!;
    srcState.children = [folderChild];
    client.getFolderTree().set(SRC_IPNS, srcState);

    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [folderChild],
      movedRef: folderChild,
    });

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'subfolder-uuid');

    expect(sdkCore.resolveFileMetadata).not.toHaveBeenCalled();
    expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
  });

  it('re-encrypts AFTER publishing the destination, not before', async () => {
    // Ordering invariant: the destination must be published before the metadata is
    // re-keyed, so the file is never sealed under the destination key while only the
    // source still points at it.
    // Tag each publish by its target folder so the assertion distinguishes the
    // destination publish from the source publish — otherwise a wrong
    // source → reencrypt → destination sequence would still satisfy a bare
    // ['publish', 'reencrypt', 'publish'].
    const order: string[] = [];
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (p) => {
      order.push(p.ipnsName === DEST_IPNS ? 'publish:dest' : 'publish:source');
      return { cid: 'bafynew', newSequenceNumber: 2n, publishedChildren: [] };
    });
    vi.mocked(sdkCore.updateFileMetadata).mockImplementation(async () => {
      order.push('reencrypt');
      return {
        ipnsName: FILE_META_IPNS,
        metadataCid: 'bafymeta2',
        newSequenceNumber: 2n,
        prunedCids: [],
      };
    });

    await client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID);

    // publish (dest) → reencrypt → publish (source)
    expect(order).toEqual(['publish:dest', 'reencrypt', 'publish:source']);
  });

  // ── failure paths ──────────────────────────────────────────────────────────
  // Order is: publish dest → re-encrypt → publish source. At every failure point
  // the file stays readable from a folder that still lists it under the matching
  // key, and the move rejects without advancing internal state.

  it('aborts cleanly when the destination publish fails (re-encrypt never runs)', async () => {
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockRejectedValueOnce(
      new Error('dest publish failed')
    );

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID)).rejects.toThrow();

    // Best case: nothing was re-keyed; the file is untouched and fully readable
    // from the source, retry is clean.
    expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
    expect(client.getFolderTree().get(SRC_IPNS)!.children).toHaveLength(1);
    expect(client.getFolderTree().get(DEST_IPNS)!.children).toHaveLength(0);
  });

  it('rejects after the destination publish when unwrapKey fails (file still readable from source)', async () => {
    vi.mocked(unwrapKey).mockRejectedValueOnce(new Error('bad key'));

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID)).rejects.toThrow();

    // Dest was published, re-encrypt aborted before touching the metadata, source
    // not yet removed → metadata still under the source key, source still lists it.
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
    expect(sdkCore.resolveFileMetadata).not.toHaveBeenCalled();
    expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
    expect(client.getFolderTree().get(SRC_IPNS)!.children).toHaveLength(1);
  });

  it('rejects after the destination publish when updateFileMetadata fails (file still readable from source)', async () => {
    vi.mocked(sdkCore.updateFileMetadata).mockRejectedValueOnce(new Error('publish failed'));

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID)).rejects.toThrow();

    // Dest published, re-encrypt failed, source publish never reached → metadata
    // still under the source key (re-encrypt did not commit), source still lists it.
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
    expect(client.getFolderTree().get(SRC_IPNS)!.children).toHaveLength(1);
  });

  it('rejects when the source publish fails after re-encryption (file readable from destination)', async () => {
    // Dest publish (call 1) succeeds, source publish (call 2) fails.
    vi.mocked(sdkCore.updateFolderMetadataAndPublish)
      .mockResolvedValueOnce({ cid: 'bafydest', newSequenceNumber: 2n, publishedChildren: [] })
      .mockRejectedValueOnce(new Error('source publish failed'));

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID)).rejects.toThrow();

    // Worst remaining case is benign: the metadata is re-keyed to the destination
    // and the destination lists the file → readable from the destination. Only the
    // stale source pointer is broken, and a retry of the source publish completes it.
    expect(sdkCore.updateFileMetadata).toHaveBeenCalledTimes(1);
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(2);
    // Internal state not advanced (move did not fully complete).
    expect(client.getFolderTree().get(SRC_IPNS)!.children).toHaveLength(1);
  });

  // ── idempotent retry ─────────────────────────────────────────────────────
  // After a partial failure that already re-keyed the record, a retry must
  // COMPLETE the move rather than throw: the source-key resolve fails, so the
  // re-key falls back to confirming the record under the destination key and
  // treats the re-encryption as done.

  const decryptionFailed = () =>
    Object.assign(new Error('Decryption failed'), { code: 'DECRYPTION_FAILED' });

  it('completes idempotently when the metadata was already re-keyed (retry after a partial move)', async () => {
    // Source-key resolve fails (already re-keyed by a prior attempt); the
    // dest-key resolve then succeeds → treat as already re-encrypted.
    vi.mocked(sdkCore.resolveFileMetadata)
      .mockRejectedValueOnce(decryptionFailed())
      .mockResolvedValueOnce({ metadata: mockFileMeta, metadataCid: 'bafymeta1' });

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID)).resolves.toBeUndefined();

    // Resolve tried the source key, then fell back to the destination key.
    expect(sdkCore.resolveFileMetadata).toHaveBeenCalledTimes(2);
    expect(vi.mocked(sdkCore.resolveFileMetadata).mock.calls[0][1]).toEqual(SRC_FOLDER_KEY);
    expect(vi.mocked(sdkCore.resolveFileMetadata).mock.calls[1][1]).toEqual(DEST_FOLDER_KEY);
    // Already re-keyed → no re-publish of the file metadata...
    expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
    // ...but the move still completes: dest add + source remove both published.
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(2);
  });

  it('rejects when the metadata is undecryptable under both the source and destination keys', async () => {
    vi.mocked(sdkCore.resolveFileMetadata)
      .mockRejectedValueOnce(decryptionFailed())
      .mockRejectedValueOnce(decryptionFailed());

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID)).rejects.toThrow();

    expect(sdkCore.resolveFileMetadata).toHaveBeenCalledTimes(2);
    expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
    // Dest published (step 2); source publish (step 4) never reached.
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('propagates a non-decrypt resolve error without attempting the dest-key fallback', async () => {
    vi.mocked(sdkCore.resolveFileMetadata).mockRejectedValueOnce(
      new Error('File metadata IPNS not found')
    );

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, FILE_ID)).rejects.toThrow(
      'File metadata IPNS not found'
    );

    // Only the source-key resolve was attempted — no fallback for a non-decrypt error.
    expect(sdkCore.resolveFileMetadata).toHaveBeenCalledTimes(1);
    expect(sdkCore.updateFileMetadata).not.toHaveBeenCalled();
  });
});
