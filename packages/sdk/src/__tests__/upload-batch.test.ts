/**
 * Tests for CipherBoxClient.uploadFiles() batch upload orchestration.
 *
 * Phase 37 Plan 01: Verifies parallel encrypt+pin via p-limit pool,
 * single folder publish, stale-children re-read, partial failure handling,
 * per-file callbacks, event emission, and key cleanup.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig, setupFolder } from './helpers';

// Mock crypto (clearBytes used in uploadFiles for key cleanup).
// Partial mock: the 68.1-22 re-read test builds a real sealed fixture via
// sealNode, which needs the genuine buildNodeAad/seal primitives.
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  };
});

// Mock sdk-core
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    resolveIpnsRecord: vi.fn(),
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
}));

// Mock share module
vi.mock('../share', () => ({
  createShareKey: vi.fn(),
  revokeShare: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';
import { clearBytes } from '@cipherbox/crypto';
import { sealNode } from '@cipherbox/core';
import type { SealedChildRef } from '@cipherbox/core';

function makeUploadResult(index: number): sdkCore.UploadResult {
  return {
    cid: `bafyfile${index}`,
    encryptedSize: 1024 * (index + 1),
    fileMetaIpnsName: `k51filemeta${index}`,
    ipnsRecord: {
      ipnsName: `k51filemeta${index}`,
      recordBase64: `base64record${index}`,
      metadataCid: `bafymeta${index}`,
    },
    ipnsPrivateKeyEncrypted: `enc-key-${index}`,
    fileKey: new Uint8Array(32).fill(0x42 + index),
    // node/v3 contract (68.1-07/09): fileReadKey/fileWriteKey are independent,
    // freshly-minted keys distinct from the content-encryption fileKey. The
    // uploadFiles seal site consumes fileReadKey (68.1-17) and the finally
    // block zeroes all three.
    fileNodeId: `0000000${index}-0000-4000-8000-000000000000`,
    fileReadKey: new Uint8Array(32).fill(0x52 + index),
    fileWriteKey: new Uint8Array(32).fill(0x62 + index),
  };
}

function setupBatchMocks(fileCount: number, failIndices: number[] = []) {
  let callIndex = 0;
  vi.mocked(sdkCore.uploadFile).mockImplementation(async () => {
    const idx = callIndex++;
    if (failIndices.includes(idx)) {
      throw new Error(`Upload failed for file ${idx}`);
    }
    return makeUploadResult(idx);
  });

  vi.mocked(sdkCore.addFilePointerToFolder).mockImplementation(async ({ children, name }) => {
    const newRef: SealedChildRef = {
      name,
      ipnsName: `k51-${name}`,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'c2VhbGVk',
    };
    return {
      updatedChildren: [...children, newRef],
      newRef,
    };
  });

  vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
    cid: 'bafyfolder-updated',
    newSequenceNumber: 2n,
    publishedChildren: [],
  });

  vi.mocked(sdkCore.batchPublishIpnsRecords).mockResolvedValue({
    totalSucceeded: fileCount - failIndices.length,
    totalFailed: 0,
  });
}

function makeTestFiles(count: number) {
  return Array.from({ length: count }, (_, i) => ({
    data: new Uint8Array([i + 1, i + 2, i + 3]),
    fileName: `file${i}.txt`,
    mimeType: 'text/plain',
  }));
}

describe('CipherBoxClient.uploadFiles - batch upload orchestration', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('uploads N files with UPLOAD_CONCURRENCY=3 concurrency pool', async () => {
    setupFolder(client);
    setupBatchMocks(5);

    // Track concurrent active uploads
    let activeCount = 0;
    let maxConcurrent = 0;

    vi.mocked(sdkCore.uploadFile).mockImplementation(async () => {
      activeCount++;
      maxConcurrent = Math.max(maxConcurrent, activeCount);
      // Simulate async work
      await new Promise((r) => setTimeout(r, 10));
      activeCount--;
      return makeUploadResult(0);
    });

    // Also mock loadFolderMetadata for the stale-children re-read
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const files = makeTestFiles(5);
    await client.uploadFiles('folder-ipns', files);

    // All 5 files should have been uploaded
    expect(sdkCore.uploadFile).toHaveBeenCalledTimes(5);

    // Concurrency should be capped at 3
    expect(maxConcurrent).toBeLessThanOrEqual(3);
  });

  it('calls updateFolderMetadataAndPublish exactly once for 5 files', async () => {
    setupFolder(client);
    setupBatchMocks(5);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const files = makeTestFiles(5);
    await client.uploadFiles('folder-ipns', files);

    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('re-reads folder state (read + write body) before publish (D-05 / 68.1-22)', async () => {
    setupFolder(client);
    setupBatchMocks(3);

    // 68.1-22: the pre-publish refresh now goes through
    // refreshFolderStateFromNetwork (resolveIpnsRecord + fetchFromIpfs +
    // real unsealNode) so the write-body mirror refreshes alongside the
    // read-body children — a read-only loadFolderMetadata refresh silently
    // republished a stale write chain at the fresh sequence.
    const folderKey = new Uint8Array(32).fill(1); // matches setupFolder
    const freshNode = {
      schema: 'node/v3' as const,
      kind: 'folder' as const,
      id: '11111111-1111-4111-8111-111111111111',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [
        {
          name: 'concurrent.txt',
          ipnsName: 'k51concurrent',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'c2VhbGVk',
        },
      ],
    };
    const published = await sealNode(freshNode, folderKey, new Uint8Array(32));
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValueOnce({
      cid: 'bafyfresh',
      sequenceNumber: 5n,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValueOnce(
      new TextEncoder().encode(JSON.stringify(published))
    );

    const files = makeTestFiles(3);
    await client.uploadFiles('folder-ipns', files);

    // The refresh resolves the folder's current record before publish
    expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledWith('folder-ipns', expect.anything());

    // The fresh sequence number should be used in the publish call
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledWith(
      expect.objectContaining({ sequenceNumber: 5n })
    );
  });

  it('publishes only successful files on partial failure (D-09)', async () => {
    setupFolder(client);
    setupBatchMocks(5, [1, 3]); // files at index 1 and 3 fail
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const files = makeTestFiles(5);
    const result = await client.uploadFiles('folder-ipns', files);

    // 3 successes, 2 failures
    expect(result.successes).toHaveLength(3);
    expect(result.failures).toHaveLength(2);
    expect(result.failures[0].fileName).toBe('file1.txt');
    expect(result.failures[1].fileName).toBe('file3.txt');

    // addFilePointerToFolder called once per success (3 times)
    expect(sdkCore.addFilePointerToFolder).toHaveBeenCalledTimes(3);

    // Still publishes (partial success)
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('skips publish when all files fail', async () => {
    setupFolder(client);
    setupBatchMocks(3, [0, 1, 2]); // all fail
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const files = makeTestFiles(3);
    const result = await client.uploadFiles('folder-ipns', files);

    expect(result.successes).toHaveLength(0);
    expect(result.failures).toHaveLength(3);

    // No publish should have been called
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
    expect(sdkCore.addFilePointerToFolder).not.toHaveBeenCalled();
  });

  it('fires per-file progress and completion callbacks', async () => {
    setupFolder(client);
    setupBatchMocks(2);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    // Capture the onProgress callback passed to sdkCore.uploadFile
    vi.mocked(sdkCore.uploadFile).mockImplementation(async (params) => {
      // Simulate progress callbacks
      params.onProgress?.(50);
      params.onProgress?.(100);
      return makeUploadResult(0);
    });

    const progressCalls: Array<{ fileName: string; percent: number }> = [];
    const completeCalls: string[] = [];

    const files = makeTestFiles(2);
    await client.uploadFiles('folder-ipns', files, {
      onFileProgress: (fileName, percent) => progressCalls.push({ fileName, percent }),
      onFileComplete: (fileName) => completeCalls.push(fileName),
    });

    // Each file should get progress callbacks
    expect(progressCalls.length).toBeGreaterThanOrEqual(4); // 2 progress calls per file
    expect(completeCalls).toHaveLength(2);
    expect(completeCalls).toContain('file0.txt');
    expect(completeCalls).toContain('file1.txt');
  });

  it('emits files:batchUploaded event with successes and failures', async () => {
    setupFolder(client);
    setupBatchMocks(3, [1]); // file at index 1 fails
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const events: Array<{ type: string; successes?: unknown[]; failures?: unknown[] }> = [];
    client.on((e) => events.push(e as (typeof events)[0]));

    const files = makeTestFiles(3);
    await client.uploadFiles('folder-ipns', files);

    const batchEvent = events.find((e) => e.type === 'files:batchUploaded');
    expect(batchEvent).toBeDefined();
    expect(batchEvent!.successes).toHaveLength(2);
    expect(batchEvent!.failures).toHaveLength(1);
  });

  it('clears file keys in finally block', async () => {
    setupFolder(client);
    setupBatchMocks(3);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const files = makeTestFiles(3);
    await client.uploadFiles('folder-ipns', files);

    // clearBytes should be called for each successful upload's three keys
    // (fileKey content key + fileReadKey/fileWriteKey node keys, 68.1-17)
    expect(clearBytes).toHaveBeenCalledTimes(9);
    for (const [arg] of vi.mocked(clearBytes).mock.calls) {
      expect(arg).toBeInstanceOf(Uint8Array);
      expect((arg as Uint8Array).length).toBe(32);
    }
  });

  it('fires onFileError callback for failed files', async () => {
    setupFolder(client);
    setupBatchMocks(3, [1]); // file at index 1 fails
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const errorCalls: Array<{ fileName: string; error: string }> = [];

    const files = makeTestFiles(3);
    await client.uploadFiles('folder-ipns', files, {
      onFileError: (fileName, error) => errorCalls.push({ fileName, error }),
    });

    expect(errorCalls).toHaveLength(1);
    expect(errorCalls[0].fileName).toBe('file1.txt');
    expect(errorCalls[0].error).toContain('Upload failed');
  });

  it('handles addFilePointerToFolder collision gracefully', async () => {
    setupFolder(client);
    setupBatchMocks(3);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    // Second call throws a name collision
    let callCount = 0;
    vi.mocked(sdkCore.addFilePointerToFolder).mockImplementation(async ({ children, name }) => {
      callCount++;
      if (callCount === 2) {
        throw new Error('An item with this name already exists');
      }
      const newRef: SealedChildRef = {
        name,
        ipnsName: `k51-${name}`,
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'c2VhbGVk',
      };
      return {
        updatedChildren: [...children, newRef],
        newRef,
      };
    });

    const errorCalls: Array<{ fileName: string; error: string }> = [];
    const files = makeTestFiles(3);
    const result = await client.uploadFiles('folder-ipns', files, {
      onFileError: (fileName, error) => errorCalls.push({ fileName, error }),
    });

    // 2 successes (files 0 and 2), 1 collision failure (file 1)
    expect(result.successes).toHaveLength(2);
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0].error).toContain('already exists');
    expect(errorCalls).toHaveLength(1);
    // Folder still publishes with the 2 successful files
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('skips publish when all addFilePointerToFolder calls collide', async () => {
    setupFolder(client);
    setupBatchMocks(2);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    vi.mocked(sdkCore.addFilePointerToFolder).mockImplementation(() => {
      throw new Error('An item with this name already exists');
    });

    const files = makeTestFiles(2);
    const result = await client.uploadFiles('folder-ipns', files);

    expect(result.successes).toHaveLength(0);
    expect(result.failures).toHaveLength(2);
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('throws when folder publish fails', async () => {
    setupFolder(client);
    setupBatchMocks(2);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockRejectedValue(
      new Error('IPNS publish timeout')
    );

    const files = makeTestFiles(2);
    await expect(client.uploadFiles('folder-ipns', files)).rejects.toThrow('IPNS publish timeout');
  });

  it('emits ipns:batchPublishFailed when batch IPNS publish rejects', async () => {
    setupFolder(client);
    setupBatchMocks(2);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);
    vi.mocked(sdkCore.batchPublishIpnsRecords).mockRejectedValue(new Error('IPNS batch timeout'));

    const events: Array<{ type: string; error?: Error }> = [];
    client.on((e) => events.push(e as (typeof events)[0]));

    const files = makeTestFiles(2);
    const result = await client.uploadFiles('folder-ipns', files);

    // Upload still succeeds (batch IPNS publish is non-critical)
    expect(result.successes).toHaveLength(2);
    const failEvent = events.find((e) => e.type === 'ipns:batchPublishFailed');
    expect(failEvent).toBeDefined();
    expect(failEvent!.error!.message).toBe('IPNS batch timeout');
  });

  it('emits ipns:batchPublishFailed on partial batch IPNS failure', async () => {
    setupFolder(client);
    setupBatchMocks(2);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);
    vi.mocked(sdkCore.batchPublishIpnsRecords).mockResolvedValue({
      totalSucceeded: 1,
      totalFailed: 1,
    });

    const events: Array<{ type: string; error?: Error }> = [];
    client.on((e) => events.push(e as (typeof events)[0]));

    const files = makeTestFiles(2);
    const result = await client.uploadFiles('folder-ipns', files);

    expect(result.successes).toHaveLength(2);
    const failEvent = events.find((e) => e.type === 'ipns:batchPublishFailed');
    expect(failEvent).toBeDefined();
    expect(failEvent!.error!.message).toContain('partial failure');
  });

  it('uses BYO-IPFS pinFn when external provider is configured', async () => {
    const byoClient = new CipherBoxClient(
      createTestConfig({
        pinningConfig: {
          mode: 'dual',
          externalProvider: {
            endpoint: 'https://byo.example.com',
            authToken: 'test-token',
            protocol: 'kubo',
          },
        },
      })
    );
    setupFolder(byoClient);
    setupBatchMocks(1);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const files = makeTestFiles(1);
    await byoClient.uploadFiles('folder-ipns', files);

    // sdkCore.uploadFile should receive a pinFn (the BYO wrapper)
    expect(sdkCore.uploadFile).toHaveBeenCalledWith(
      expect.objectContaining({
        pinFn: expect.any(Function),
      })
    );
  });

  it('uses custom pinFn from options when provided', async () => {
    setupFolder(client);
    setupBatchMocks(1);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const customPinFn = vi.fn().mockResolvedValue({ cid: 'bafycustom', size: 100 });

    const files = makeTestFiles(1);
    await client.uploadFiles('folder-ipns', files, {}, { pinFn: customPinFn });

    // sdkCore.uploadFile should receive the custom pinFn
    expect(sdkCore.uploadFile).toHaveBeenCalledWith(
      expect.objectContaining({ pinFn: customPinFn })
    );
  });

  it('handles non-Error rejection from batch IPNS publish', async () => {
    setupFolder(client);
    setupBatchMocks(1);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);
    vi.mocked(sdkCore.batchPublishIpnsRecords).mockRejectedValue('string error');

    const events: Array<{ type: string; error?: Error }> = [];
    client.on((e) => events.push(e as (typeof events)[0]));

    const files = makeTestFiles(1);
    const result = await client.uploadFiles('folder-ipns', files);

    expect(result.successes).toHaveLength(1);
    const failEvent = events.find((e) => e.type === 'ipns:batchPublishFailed');
    expect(failEvent).toBeDefined();
    expect(failEvent!.error!.message).toBe('string error');
  });

  it('completes upload even when shareCallbacks configured (no re-wrapping)', async () => {
    const getCoveringShares = vi.fn().mockRejectedValue(new Error('share lookup failed'));
    const addShareKeys = vi.fn();
    const shareClient = new CipherBoxClient(
      createTestConfig({
        shareCallbacks: { getCoveringShares, addShareKeys },
      })
    );
    setupFolder(shareClient);
    setupBatchMocks(1);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const files = makeTestFiles(1);
    // Should succeed — D-03 removed per-recipient fan-out, so getCoveringShares is never called
    const result = await shareClient.uploadFiles('folder-ipns', files);
    expect(result.successes).toHaveLength(1);
    expect(getCoveringShares).not.toHaveBeenCalled();
  });

  it('emits folder:updated event after successful batch publish', async () => {
    setupFolder(client);
    setupBatchMocks(2);
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const events: Array<{ type: string; sequenceNumber?: bigint }> = [];
    client.on((e) => events.push(e as (typeof events)[0]));

    const files = makeTestFiles(2);
    await client.uploadFiles('folder-ipns', files);

    const folderEvent = events.find((e) => e.type === 'folder:updated');
    expect(folderEvent).toBeDefined();
    expect(folderEvent!.sequenceNumber).toBe(2n);
  });
});
