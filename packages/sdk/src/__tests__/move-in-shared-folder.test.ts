/**
 * TDD test (49-01 RED): moveInSharedFolder op + CipherBoxClient.moveInSharedFolder
 *
 * Covers:
 * - Publish ordering: DEST published before SOURCE (add-before-remove crash safety)
 * - File re-key: reencryptFileMetadataForFolderChange called with correct src/dest folderKeys
 * - Folder item: no re-key call
 * - Missing folder-ipns key on dest: throws before any publish (T-49-01 write-cap guard)
 * - Missing folder key on dest: throws (no read key)
 * - Name collision: propagated
 * - adoptSharedFolderResult for SOURCE only (never dest)
 * - finally: fileIpnsPrivateKey.fill(0), destIpnsPrivateKey.fill(0), destFolderKey.fill(0)
 *   all run even when the op throws
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import type { SdkEvent } from '../events';
import type { SharedFolderState } from '../types';
import type { FolderChild, FilePointer, FolderEntry } from '@cipherbox/core';
import { createTestConfig } from './helpers';

// ── crypto mock ────────────────────────────────────────────────────────────────
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xab)),
  hexToBytes: vi.fn((hex: string) => new Uint8Array(Math.max(hex.length / 2, 1)).fill(0x01)),
}));

// ── sdk-core mock ─────────────────────────────────────────────────────────────
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    moveItem: vi.fn(),
    // keep real implementations silent for unused ops
    createSubfolder: vi.fn(),
    renameInFolder: vi.fn(),
    deleteFromFolder: vi.fn(),
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

// ── bin / share mocks (not under test) ───────────────────────────────────────
vi.mock('../bin', () => ({
  loadBin: vi.fn(),
  addToBin: vi.fn(),
  restoreFromBin: vi.fn(),
  permanentDeleteFromBin: vi.fn(),
  emptyBin: vi.fn(),
  purgeExpiredEntries: vi.fn(),
}));

vi.mock('../share', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../share')>();
  return {
    ...actual,
    // Keep real shared-write exports so the stateless op is exercised;
    // stub only the ops we don't want to call in network.
    uploadToSharedFolder: vi.fn(),
  };
});

// ── reencrypt mock ────────────────────────────────────────────────────────────
vi.mock('../reencrypt', () => ({
  reencryptFileMetadataForFolderChange: vi.fn().mockResolvedValue(undefined),
}));

import * as sdkCore from '@cipherbox/sdk-core';
import * as reencryptModule from '../reencrypt';
import { unwrapKey } from '@cipherbox/crypto';

// ── constants ─────────────────────────────────────────────────────────────────
const SHARE_ID = 'share-abc';
const SRC_IPNS = 'k51src-shared';
const DEST_IPNS = 'k51dest-shared';
const DEST_FOLDER_ID = 'dest-folder-uuid';
const FILE_ID = 'file-uuid-shared';
const FOLDER_ITEM_ID = 'folder-item-uuid';
const FILE_META_IPNS = 'k51filemeta-shared';
const FILE_IPNS_KEY_ENC = 'deadbeef0102';
const DEST_FOLDER_KEY_ENC = 'cafecafe0102';
const DEST_IPNS_KEY_ENC = 'beefdead0102';

const SRC_FOLDER_KEY = new Uint8Array(32).fill(0x11);
const SRC_IPNS_KEY = new Uint8Array(64).fill(0x22);
const DEST_FOLDER_KEY_BYTES = new Uint8Array(32).fill(0x33);
const DEST_IPNS_KEY_BYTES = new Uint8Array(64).fill(0x44);

const now = Date.now();

const fileItem: FilePointer = {
  type: 'file',
  id: FILE_ID,
  name: 'document.txt',
  fileMetaIpnsName: FILE_META_IPNS,
  ipnsPrivateKeyEncrypted: FILE_IPNS_KEY_ENC,
  createdAt: now,
  modifiedAt: now,
};

const folderItem: FolderEntry = {
  type: 'folder',
  id: FOLDER_ITEM_ID,
  name: 'subfolder',
  ipnsName: 'k51subfolder-item',
  folderKeyEncrypted: 'ff0011',
  ipnsPrivateKeyEncrypted: 'ff0022',
  createdAt: now,
  modifiedAt: now,
};

// share_keys factory: generates entries for the given opts
type ShareKeyEntry = { keyType: string; itemId: string; encryptedKey: string };

function makeShareKeys(opts: {
  destFolder?: boolean;
  destFolderIpns?: boolean;
  fileIpns?: boolean;
}): ShareKeyEntry[] {
  const keys: ShareKeyEntry[] = [];
  if (opts.destFolder) {
    keys.push({ keyType: 'folder', itemId: DEST_FOLDER_ID, encryptedKey: DEST_FOLDER_KEY_ENC });
  }
  if (opts.destFolderIpns) {
    keys.push({
      keyType: 'folder-ipns',
      itemId: DEST_FOLDER_ID,
      encryptedKey: DEST_IPNS_KEY_ENC,
    });
  }
  if (opts.fileIpns) {
    keys.push({
      keyType: 'file-ipns',
      itemId: FILE_ID,
      encryptedKey: FILE_IPNS_KEY_ENC,
    });
  }
  return keys;
}

function seedSharedFolder(
  client: CipherBoxClient,
  children: FolderChild[],
  overrides?: Partial<SharedFolderState>
): SharedFolderState {
  const state: SharedFolderState = {
    shareId: SHARE_ID,
    ipnsName: SRC_IPNS,
    folderKey: new Uint8Array(SRC_FOLDER_KEY),
    ipnsPrivateKey: new Uint8Array(SRC_IPNS_KEY),
    sequenceNumber: 5n,
    children,
    ownerPublicKey: new Uint8Array(33).fill(0x03),
    recipientPublicKey: new Uint8Array(33).fill(0x04),
    addShareKeysFn: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
  client.loadSharedFolder(state.shareId, state);
  return state;
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('CipherBoxClient.moveInSharedFolder', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());

    // Default: unwrapKey returns distinct buffers for dest folder key vs dest ipns key
    // (first call → dest folderKey, second → dest ipnsPrivateKey, third → file-ipns key)
    vi.mocked(unwrapKey)
      .mockResolvedValueOnce(new Uint8Array(DEST_FOLDER_KEY_BYTES))
      .mockResolvedValueOnce(new Uint8Array(DEST_IPNS_KEY_BYTES))
      .mockResolvedValue(new Uint8Array(32).fill(0x55)); // file-ipns key

    // loadFolderMetadata returns fresh dest state
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue({
      metadata: { children: [] } as never,
      sequenceNumber: 10n,
      cid: 'bafydest',
    });

    // moveItem returns successful mutation
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSourceChildren: [],
      updatedDestChildren: [fileItem],
      movedItem: fileItem,
    });

    // updateFolderMetadataAndPublish returns new sequences
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 11n,
      publishedChildren: [],
    });
  });

  // ── publish ordering ───────────────────────────────────────────────────────

  it('publishes DEST before SOURCE (add-before-remove crash safety)', async () => {
    seedSharedFolder(client, [fileItem]);
    const order: string[] = [];
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (p) => {
      order.push(p.ipnsName === DEST_IPNS ? 'dest' : 'source');
      return { cid: 'bafynew', newSequenceNumber: 11n, publishedChildren: [] };
    });

    await client.moveInSharedFolder(SHARE_ID, {
      itemId: FILE_ID,
      destFolderId: DEST_FOLDER_ID,
      destIpnsName: DEST_IPNS,
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
      getShareKeysFn: async () =>
        makeShareKeys({ destFolder: true, destFolderIpns: true, fileIpns: true }),
    });

    expect(order).toEqual(['dest', 'source']);
  });

  // ── file re-key ────────────────────────────────────────────────────────────

  it('calls reencryptFileMetadataForFolderChange with src and dest folderKeys for file item', async () => {
    seedSharedFolder(client, [fileItem]);

    // Capture snapshots at call time — the buffers are zeroed in finally
    let capturedSourceFolderKey: Uint8Array | undefined;
    let capturedDestFolderKey: Uint8Array | undefined;
    let capturedFileMetaIpnsName: string | undefined;
    vi.mocked(reencryptModule.reencryptFileMetadataForFolderChange).mockImplementation(
      async (p) => {
        capturedSourceFolderKey = new Uint8Array(p.sourceFolderKey);
        capturedDestFolderKey = new Uint8Array(p.destFolderKey);
        capturedFileMetaIpnsName = p.fileMetaIpnsName;
      }
    );

    await client.moveInSharedFolder(SHARE_ID, {
      itemId: FILE_ID,
      destFolderId: DEST_FOLDER_ID,
      destIpnsName: DEST_IPNS,
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
      getShareKeysFn: async () =>
        makeShareKeys({ destFolder: true, destFolderIpns: true, fileIpns: true }),
    });

    expect(reencryptModule.reencryptFileMetadataForFolderChange).toHaveBeenCalledTimes(1);
    expect(capturedFileMetaIpnsName).toBe(FILE_META_IPNS);
    // sourceFolderKey must be the SOURCE folder key (from sharedFolderTree)
    expect(capturedSourceFolderKey).toEqual(SRC_FOLDER_KEY);
    // destFolderKey must be what was unwrapped from share_keys for destFolderId
    expect(capturedDestFolderKey).toEqual(DEST_FOLDER_KEY_BYTES);
  });

  it('file IPNS key is resolved from share_keys keyType:file-ipns (NEVER FilePointer.ipnsPrivateKeyEncrypted)', async () => {
    seedSharedFolder(client, [fileItem]);
    // Reset unwrapKey to provide exactly 3 calls in sequence (no interference from beforeEach queue)
    const fileIpnsBytes = new Uint8Array(32).fill(0x77);
    vi.mocked(unwrapKey).mockReset();
    vi.mocked(unwrapKey)
      .mockResolvedValueOnce(new Uint8Array(DEST_FOLDER_KEY_BYTES)) // 1st: dest folder key
      .mockResolvedValueOnce(new Uint8Array(DEST_IPNS_KEY_BYTES)) // 2nd: dest ipns key
      .mockResolvedValueOnce(new Uint8Array(fileIpnsBytes)); // 3rd: file-ipns key from share_keys

    // Capture the fileIpnsPrivateKey snapshot before finally zeroes it
    let capturedFileIpnsKey: Uint8Array | undefined;
    vi.mocked(reencryptModule.reencryptFileMetadataForFolderChange).mockImplementation(
      async (p) => {
        capturedFileIpnsKey = new Uint8Array(p.fileIpnsPrivateKey);
      }
    );

    await client.moveInSharedFolder(SHARE_ID, {
      itemId: FILE_ID,
      destFolderId: DEST_FOLDER_ID,
      destIpnsName: DEST_IPNS,
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
      getShareKeysFn: async () =>
        makeShareKeys({ destFolder: true, destFolderIpns: true, fileIpns: true }),
    });

    // fileIpnsPrivateKey must be from share_keys (value 0x77), not FilePointer (0x01)
    expect(capturedFileIpnsKey).toEqual(fileIpnsBytes);
    // Must have called unwrapKey exactly 3 times: destFolderKey, destIpnsKey, fileIpnsKey
    expect(vi.mocked(unwrapKey)).toHaveBeenCalledTimes(3);
  });

  it('does NOT call reencryptFileMetadataForFolderChange for folder item', async () => {
    seedSharedFolder(client, [folderItem]);
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSourceChildren: [],
      updatedDestChildren: [folderItem],
      movedItem: folderItem,
    });

    await client.moveInSharedFolder(SHARE_ID, {
      itemId: FOLDER_ITEM_ID,
      destFolderId: DEST_FOLDER_ID,
      destIpnsName: DEST_IPNS,
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
      getShareKeysFn: async () => makeShareKeys({ destFolder: true, destFolderIpns: true }),
    });

    expect(reencryptModule.reencryptFileMetadataForFolderChange).not.toHaveBeenCalled();
  });

  // ── write-capability guard (T-49-01) ───────────────────────────────────────

  it('throws before any publish when dest is missing keyType:folder-ipns (no write key)', async () => {
    seedSharedFolder(client, [fileItem]);

    await expect(
      client.moveInSharedFolder(SHARE_ID, {
        itemId: FILE_ID,
        destFolderId: DEST_FOLDER_ID,
        destIpnsName: DEST_IPNS,
        vaultPrivateKey: new Uint8Array(32).fill(0x99),
        // Missing folder-ipns key
        getShareKeysFn: async () => makeShareKeys({ destFolder: true, fileIpns: true }),
      })
    ).rejects.toThrow(/No write key for destination folder/);

    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('throws before any publish when dest is missing keyType:folder (no read key)', async () => {
    seedSharedFolder(client, [fileItem]);

    await expect(
      client.moveInSharedFolder(SHARE_ID, {
        itemId: FILE_ID,
        destFolderId: DEST_FOLDER_ID,
        destIpnsName: DEST_IPNS,
        vaultPrivateKey: new Uint8Array(32).fill(0x99),
        // Missing folder key
        getShareKeysFn: async () => makeShareKeys({ destFolderIpns: true, fileIpns: true }),
      })
    ).rejects.toThrow(/No read key for destination folder/);

    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  // ── name collision ─────────────────────────────────────────────────────────

  it('propagates name collision error from moveItem without publishing', async () => {
    seedSharedFolder(client, [fileItem]);
    vi.mocked(sdkCore.moveItem).mockImplementation(() => {
      throw new Error('An item with this name already exists in destination');
    });

    await expect(
      client.moveInSharedFolder(SHARE_ID, {
        itemId: FILE_ID,
        destFolderId: DEST_FOLDER_ID,
        destIpnsName: DEST_IPNS,
        vaultPrivateKey: new Uint8Array(32).fill(0x99),
        getShareKeysFn: async () =>
          makeShareKeys({ destFolder: true, destFolderIpns: true, fileIpns: true }),
      })
    ).rejects.toThrow('An item with this name already exists in destination');

    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  // ── adoptSharedFolderResult for SOURCE only ────────────────────────────────

  it('calls adoptSharedFolderResult for SOURCE result only, not dest', async () => {
    seedSharedFolder(client, [fileItem]);

    const srcPublishedChildren: FolderChild[] = [];
    const destPublishedChildren: FolderChild[] = [fileItem];

    let callIdx = 0;
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (p) => {
      callIdx++;
      const seq = callIdx === 1 ? 20n : 21n; // dest=20n, source=21n
      const children = p.ipnsName === DEST_IPNS ? destPublishedChildren : srcPublishedChildren;
      return { cid: 'bafynew', newSequenceNumber: seq, publishedChildren: children };
    });

    const events: SdkEvent[] = [];
    client.on((e) => events.push(e));

    await client.moveInSharedFolder(SHARE_ID, {
      itemId: FILE_ID,
      destFolderId: DEST_FOLDER_ID,
      destIpnsName: DEST_IPNS,
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
      getShareKeysFn: async () =>
        makeShareKeys({ destFolder: true, destFolderIpns: true, fileIpns: true }),
    });

    // Should emit exactly one sharedFolder:updated event for the SOURCE
    const updates = events.filter((e) => e.type === 'sharedFolder:updated');
    expect(updates).toHaveLength(1);
    const update = updates[0] as Extract<SdkEvent, { type: 'sharedFolder:updated' }>;
    // Source result: sequence=21n, children=[]
    expect(update.sequenceNumber).toBe(21n);
    expect(update.children).toEqual(srcPublishedChildren);
    // Must emit with the SOURCE ipnsName, not dest
    expect(update.ipnsName).toBe(SRC_IPNS);
  });

  // ── finally zeroing ────────────────────────────────────────────────────────

  it('zeroes destFolderKey, destIpnsPrivateKey, and fileIpnsPrivateKey in finally even on op failure', async () => {
    seedSharedFolder(client, [fileItem]);

    // Capture the actual key buffers returned by unwrapKey
    const destFolderKeyBuf = new Uint8Array(32).fill(0x33);
    const destIpnsKeyBuf = new Uint8Array(64).fill(0x44);
    const fileIpnsKeyBuf = new Uint8Array(32).fill(0x55);

    // Reset to provide exactly 3 calls in order (no interference from beforeEach queue)
    vi.mocked(unwrapKey).mockReset();
    vi.mocked(unwrapKey)
      .mockResolvedValueOnce(destFolderKeyBuf)
      .mockResolvedValueOnce(destIpnsKeyBuf)
      .mockResolvedValueOnce(fileIpnsKeyBuf);

    // Make the op fail after key resolution
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockRejectedValue(
      new Error('publish failed')
    );

    await expect(
      client.moveInSharedFolder(SHARE_ID, {
        itemId: FILE_ID,
        destFolderId: DEST_FOLDER_ID,
        destIpnsName: DEST_IPNS,
        vaultPrivateKey: new Uint8Array(32).fill(0x99),
        getShareKeysFn: async () =>
          makeShareKeys({ destFolder: true, destFolderIpns: true, fileIpns: true }),
      })
    ).rejects.toThrow('publish failed');

    // All three temp keys must be zeroed in the finally block
    expect(destFolderKeyBuf.every((b) => b === 0)).toBe(true);
    expect(destIpnsKeyBuf.every((b) => b === 0)).toBe(true);
    expect(fileIpnsKeyBuf.every((b) => b === 0)).toBe(true);
  });

  it('zeroes keys in finally when unwrapKey throws after partial resolution', async () => {
    seedSharedFolder(client, [fileItem]);
    // destFolderKey resolves but destIpnsPrivateKey unwrap fails
    const destFolderKeyBuf = new Uint8Array(32).fill(0x33);
    vi.mocked(unwrapKey).mockReset();
    vi.mocked(unwrapKey)
      .mockResolvedValueOnce(destFolderKeyBuf)
      .mockRejectedValueOnce(new Error('unwrap failed'));

    await expect(
      client.moveInSharedFolder(SHARE_ID, {
        itemId: FILE_ID,
        destFolderId: DEST_FOLDER_ID,
        destIpnsName: DEST_IPNS,
        vaultPrivateKey: new Uint8Array(32).fill(0x99),
        // Both keys exist so record lookup succeeds, but 2nd unwrap throws
        getShareKeysFn: async () => makeShareKeys({ destFolder: true, destFolderIpns: true }),
      })
    ).rejects.toThrow('unwrap failed');

    // destFolderKey was resolved before the throw — must be zeroed in finally
    expect(destFolderKeyBuf.every((b) => b === 0)).toBe(true);
  });

  // ── shared folder not loaded ───────────────────────────────────────────────

  it('throws "Shared folder not loaded" when share is not seeded', async () => {
    await expect(
      client.moveInSharedFolder('nonexistent-share', {
        itemId: FILE_ID,
        destFolderId: DEST_FOLDER_ID,
        destIpnsName: DEST_IPNS,
        vaultPrivateKey: new Uint8Array(32).fill(0x99),
        getShareKeysFn: async () => makeShareKeys({ destFolder: true, destFolderIpns: true }),
      })
    ).rejects.toThrow('Shared folder not loaded');
  });
});

// ── stateless op tests ────────────────────────────────────────────────────────

describe('moveInSharedFolder stateless op', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSourceChildren: [],
      updatedDestChildren: [fileItem],
      movedItem: fileItem,
    });

    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 11n,
      publishedChildren: [],
    });
  });

  it('does NOT zero any keys (caller owns zeroing)', async () => {
    // The stateless op must not zero the passed-in keys.
    // We verify that the src/dest folderKey/ipnsPrivateKey values are unchanged after the call.
    const { moveInSharedFolder: opFn } = await import('../share/shared-write');

    const srcFolderKey = new Uint8Array(32).fill(0x11);
    const srcIpnsPrivateKey = new Uint8Array(64).fill(0x22);
    const destFolderKey = new Uint8Array(32).fill(0x33);
    const destIpnsPrivateKey = new Uint8Array(64).fill(0x44);
    const fileIpnsPrivateKey = new Uint8Array(32).fill(0x55);

    const srcFolderKeySnapshot = new Uint8Array(srcFolderKey);
    const destFolderKeySnapshot = new Uint8Array(destFolderKey);

    await opFn({
      ctx: {} as never,
      srcCtx: {
        folderKey: srcFolderKey,
        ipnsPrivateKey: srcIpnsPrivateKey,
        ipnsName: SRC_IPNS,
        sequenceNumber: 1n,
        children: [fileItem],
      },
      destCtx: {
        folderKey: destFolderKey,
        ipnsPrivateKey: destIpnsPrivateKey,
        ipnsName: DEST_IPNS,
        sequenceNumber: 2n,
        children: [],
      },
      itemId: FILE_ID,
      fileIpnsPrivateKey,
    });

    // Keys must NOT be zeroed by the stateless op
    expect(srcFolderKey).toEqual(srcFolderKeySnapshot);
    expect(destFolderKey).toEqual(destFolderKeySnapshot);
    // fileIpnsPrivateKey also must NOT be zeroed by the op
    expect(fileIpnsPrivateKey.every((b) => b === 0x55)).toBe(true);
  });
});
