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

// Mock crypto (clearBytes used in uploadFiles for key cleanup)
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
}));

// Mock share module
vi.mock('../share', () => ({
  createShareKey: vi.fn(),
  revokeShare: vi.fn(),
  reWrapForRecipients: vi.fn().mockResolvedValue({ failedRecipients: [] }),
}));

import * as sdkCore from '@cipherbox/sdk-core';
import { clearBytes } from '@cipherbox/crypto';

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

  vi.mocked(sdkCore.addFilePointerToFolder).mockImplementation(({ children, fileName }) => {
    const newChild = {
      type: 'file' as const,
      id: `file-${fileName}`,
      name: fileName,
      fileMetaIpnsName: `k51-${fileName}`,
      ipnsPrivateKeyEncrypted: 'enc-key',
      createdAt: Date.now(),
      modifiedAt: Date.now(),
    };
    return {
      updatedChildren: [...children, newChild],
      filePointer: newChild,
    };
  });

  vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
    cid: 'bafyfolder-updated',
    newSequenceNumber: 2n,
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

  it('re-reads folder metadata before publish (D-05)', async () => {
    setupFolder(client);
    setupBatchMocks(3);

    // Return fresh metadata from loadFolderMetadata
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue({
      metadata: {
        version: 'v2',
        children: [
          {
            type: 'file' as const,
            id: 'concurrent-file',
            name: 'concurrent.txt',
            fileMetaIpnsName: 'k51concurrent',
            ipnsPrivateKeyEncrypted: 'enc',
            createdAt: 0,
            modifiedAt: 0,
          },
        ],
      },
      sequenceNumber: 5n,
      cid: 'bafyfresh',
    });

    const files = makeTestFiles(3);
    await client.uploadFiles('folder-ipns', files);

    // loadFolderMetadata should be called before updateFolderMetadataAndPublish
    expect(sdkCore.loadFolderMetadata).toHaveBeenCalledTimes(1);
    expect(sdkCore.loadFolderMetadata).toHaveBeenCalledWith(
      expect.objectContaining({ ipnsName: 'folder-ipns' })
    );

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

    // clearBytes should be called for each successful upload's file key
    expect(clearBytes).toHaveBeenCalledTimes(3);
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
