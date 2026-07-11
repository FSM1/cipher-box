/**
 * Tests for concurrent pin orchestration in CipherBoxClient.uploadFile().
 *
 * Phase 19.2 Plan 01: Verifies that batchPublishIpnsRecords and
 * updateFolderMetadataAndPublish execute concurrently via Promise.allSettled,
 * and that partial failures are handled correctly.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
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
}));

// Mock share module
vi.mock('../share', () => ({
  createShareKey: vi.fn(),
  revokeShare: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';

function setupUploadMocks() {
  vi.mocked(sdkCore.uploadFile).mockResolvedValue({
    cid: 'bafyfile',
    encryptedSize: 1024,
    fileMetaIpnsName: 'k51filemeta',
    ipnsRecord: {
      ipnsName: 'k51filemeta',
      recordBase64: 'base64record',
      metadataCid: 'bafymeta',
    },
    encryptedIpnsPrivateKey: 'enc-key',
    fileKey: new Uint8Array(32).fill(0x42),
    // v3 file Node fields (68.1-07/09) — the parent read/write-body seal path
    // reads these off uploadResult; the finally block also zeroes them.
    fileNodeId: 'new-file',
    fileReadKey: new Uint8Array(32).fill(0x43),
    fileWriteKey: new Uint8Array(32).fill(0x44),
  });

  vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
    updatedChildren: [
      {
        name: 'existing.txt',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'abc',
      },
      {
        name: 'new.txt',
        ipnsName: 'k51filemeta',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'enc-key',
      },
    ],
    newRef: {
      name: 'new.txt',
      ipnsName: 'k51filemeta',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'enc-key',
    },
  });
}

describe('CipherBoxClient.uploadFile - concurrent pin orchestration', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('calls batchPublishIpnsRecords and updateFolderMetadataAndPublish concurrently', async () => {
    setupFolder(client);
    setupUploadMocks();

    // Track call order to verify concurrency.
    // If calls are concurrent, both should be initiated before either resolves.
    const callLog: string[] = [];

    vi.mocked(sdkCore.batchPublishIpnsRecords).mockImplementation(async () => {
      callLog.push('batch:start');
      await Promise.resolve();
      callLog.push('batch:end');
      return { totalSucceeded: 1, totalFailed: 0 };
    });

    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async () => {
      callLog.push('folder:start');
      await Promise.resolve();
      callLog.push('folder:end');
      return { cid: 'bafyfolder', newSequenceNumber: 2n, publishedChildren: [] };
    });

    await client.uploadFile('folder-ipns', new Uint8Array([1, 2, 3]), 'new.txt', 'text/plain');

    // Both should have started before either ended (concurrent execution)
    expect(callLog.indexOf('batch:start')).toBeLessThan(callLog.indexOf('batch:end'));
    expect(callLog.indexOf('folder:start')).toBeLessThan(callLog.indexOf('folder:end'));

    // Both starts should occur before any end (concurrent, not sequential)
    const firstEnd = Math.min(callLog.indexOf('batch:end'), callLog.indexOf('folder:end'));
    expect(callLog.indexOf('batch:start')).toBeLessThan(firstEnd);
    expect(callLog.indexOf('folder:start')).toBeLessThan(firstEnd);
  });

  it('succeeds when batchPublishIpnsRecords rejects (non-critical) and logs warning', async () => {
    setupFolder(client);
    setupUploadMocks();

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    vi.mocked(sdkCore.batchPublishIpnsRecords).mockRejectedValue(
      new Error('IPNS batch publish network error')
    );
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafyfolder',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    // Should NOT throw -- batch publish failure is non-critical
    const result = await client.uploadFile(
      'folder-ipns',
      new Uint8Array([1, 2, 3]),
      'new.txt',
      'text/plain'
    );
    expect(result.cid).toBe('bafyfile');

    // Should log a warning about the failure
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[SDK] File IPNS batch publish failed'),
      expect.any(Error)
    );

    warnSpy.mockRestore();
  });

  it('throws when updateFolderMetadataAndPublish rejects (critical failure)', async () => {
    setupFolder(client);
    setupUploadMocks();

    const folderError = new Error('Folder metadata pin failed');

    vi.mocked(sdkCore.batchPublishIpnsRecords).mockResolvedValue({
      totalSucceeded: 1,
      totalFailed: 0,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockRejectedValue(folderError);

    await expect(
      client.uploadFile('folder-ipns', new Uint8Array([1, 2, 3]), 'new.txt', 'text/plain')
    ).rejects.toThrow('Folder metadata pin failed');
  });

  it('warns and emits event when batchPublishIpnsRecords reports partial failure', async () => {
    setupFolder(client);
    setupUploadMocks();

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const events: Array<{ type: string }> = [];
    client.on((e) => events.push(e));

    vi.mocked(sdkCore.batchPublishIpnsRecords).mockResolvedValue({
      totalSucceeded: 0,
      totalFailed: 1,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafyfolder',
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

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[SDK] File IPNS batch publish partially failed')
    );

    const batchEvent = events.find((e) => e.type === 'ipns:batchPublishFailed');
    expect(batchEvent).toBeDefined();

    warnSpy.mockRestore();
  });

  it('throws the folder metadata error when both reject (prioritize critical path)', async () => {
    setupFolder(client);
    setupUploadMocks();

    const folderError = new Error('Folder metadata update failed');
    const batchError = new Error('IPNS batch publish failed');

    vi.mocked(sdkCore.batchPublishIpnsRecords).mockRejectedValue(batchError);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockRejectedValue(folderError);

    await expect(
      client.uploadFile('folder-ipns', new Uint8Array([1, 2, 3]), 'new.txt', 'text/plain')
    ).rejects.toThrow('Folder metadata update failed');
  });
});
