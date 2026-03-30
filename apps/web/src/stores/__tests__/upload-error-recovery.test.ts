/**
 * Upload Error Recovery Tests
 *
 * Verifies:
 * 1. Upload store transitions to 'error' via per-file setFileStatus
 * 2. Orphaned IPFS pins are cleaned up when registration fails after successful upload
 * 3. Quota is refreshed after orphan cleanup
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useUploadStore } from '../upload.store';
import type { PendingReplacement } from '../upload.store';

const TEST_FILE = new File(['test'], 'test.txt', { type: 'text/plain' });

/**
 * Simulates the catch-block error recovery logic from useDropUpload.
 * Extracted here so we can test all branches without fighting TypeScript narrowing.
 */
function simulateErrorRecovery(
  fileId: string,
  errorMessage: string,
  uploadedFiles: { cid: string }[] | undefined,
  unpinFn: (cid: string) => Promise<void>,
  fetchQuotaFn: () => Promise<void>
) {
  if (errorMessage !== 'Upload cancelled by user') {
    useUploadStore.getState().setFileStatus(fileId, 'error', errorMessage);

    if (uploadedFiles?.length) {
      uploadedFiles.forEach((f) => unpinFn(f.cid).catch(() => {}));
      fetchQuotaFn();
    }
  }
}

describe('Upload Store - Error Recovery', () => {
  beforeEach(() => {
    useUploadStore.getState().reset();
  });

  describe('setFileStatus transitions file to error', () => {
    it('should transition a file to error state', () => {
      const testId = 'upload-file1-1234';
      useUploadStore.getState().addFile(testId, 'file1.txt', 'root', TEST_FILE);
      useUploadStore.getState().updateFileProgress(testId, 50);

      useUploadStore.getState().setFileStatus(testId, 'error', 'Duplicate filename');

      const file = useUploadStore.getState().files.get(testId);
      expect(file?.status).toBe('error');
      expect(file?.error).toBe('Duplicate filename');
    });

    it('should allow reset after error state', () => {
      const testId = 'upload-file1-1234';
      useUploadStore.getState().addFile(testId, 'file1.txt', 'root', TEST_FILE);
      useUploadStore.getState().setFileStatus(testId, 'error', 'Network error');

      expect(useUploadStore.getState().files.get(testId)?.status).toBe('error');

      useUploadStore.getState().reset();

      const state = useUploadStore.getState();
      expect(state.files.size).toBe(0);
    });
  });
});

describe('Upload Error Recovery - Orphan Cleanup Logic', () => {
  beforeEach(() => {
    useUploadStore.getState().reset();
  });

  it('should unpin each CID when registration fails after upload', () => {
    const mockUnpin = vi.fn().mockResolvedValue(undefined);
    const mockFetchQuota = vi.fn().mockResolvedValue(undefined);

    const testId = 'upload-a-1234';
    useUploadStore.getState().addFile(testId, 'a.txt', 'root', TEST_FILE);

    const uploadedFiles = [{ cid: 'QmAAA' }, { cid: 'QmBBB' }, { cid: 'QmCCC' }];

    simulateErrorRecovery(
      testId,
      'A file with name a.txt already exists',
      uploadedFiles,
      mockUnpin,
      mockFetchQuota
    );

    expect(mockUnpin).toHaveBeenCalledTimes(3);
    expect(mockUnpin).toHaveBeenCalledWith('QmAAA');
    expect(mockUnpin).toHaveBeenCalledWith('QmBBB');
    expect(mockUnpin).toHaveBeenCalledWith('QmCCC');
    expect(mockFetchQuota).toHaveBeenCalledTimes(1);
    expect(useUploadStore.getState().files.get(testId)?.status).toBe('error');
  });

  it('should NOT unpin when upload itself failed (uploadedFiles is undefined)', () => {
    const mockUnpin = vi.fn();
    const mockFetchQuota = vi.fn();

    const testId = 'upload-fail-1234';
    useUploadStore.getState().addFile(testId, 'fail.txt', 'root', TEST_FILE);

    simulateErrorRecovery(testId, 'Encryption failed', undefined, mockUnpin, mockFetchQuota);

    expect(mockUnpin).not.toHaveBeenCalled();
    expect(mockFetchQuota).not.toHaveBeenCalled();
    expect(useUploadStore.getState().files.get(testId)?.status).toBe('error');
  });

  it('should NOT unpin or set error when user cancels upload', () => {
    const mockUnpin = vi.fn();
    const mockFetchQuota = vi.fn();

    const testId = 'upload-cancel-1234';
    useUploadStore.getState().addFile(testId, 'cancel.txt', 'root', TEST_FILE);

    simulateErrorRecovery(
      testId,
      'Upload cancelled by user',
      [{ cid: 'QmAAA' }],
      mockUnpin,
      mockFetchQuota
    );

    expect(mockUnpin).not.toHaveBeenCalled();
    expect(mockFetchQuota).not.toHaveBeenCalled();
    // File should still be in its original 'encrypting' status (not error)
    expect(useUploadStore.getState().files.get(testId)?.status).toBe('encrypting');
  });

  it('should handle unpin failures gracefully (fire-and-forget)', () => {
    const mockUnpin = vi.fn().mockRejectedValue(new Error('Unpin failed'));
    const mockFetchQuota = vi.fn().mockResolvedValue(undefined);

    const testId = 'upload-unpin-fail-1234';
    useUploadStore.getState().addFile(testId, 'unpin-fail.txt', 'root', TEST_FILE);

    simulateErrorRecovery(
      testId,
      'Registration failed',
      [{ cid: 'QmFAIL' }],
      mockUnpin,
      mockFetchQuota
    );

    expect(mockUnpin).toHaveBeenCalledWith('QmFAIL');
    expect(mockFetchQuota).toHaveBeenCalledTimes(1);
  });
});

describe('Upload Store - Pending Replacements', () => {
  const testReplacement: PendingReplacement = {
    fileName: 'test.txt',
    fileId: 'file-123',
    parentId: 'root',
    encryptedData: {
      cid: 'bafytest123',
      wrappedKey: 'aa'.repeat(48),
      iv: 'bb'.repeat(12),
      size: 1024,
      encryptionMode: 'GCM',
    },
  };

  beforeEach(() => {
    useUploadStore.getState().reset();
  });

  it('starts with empty pendingReplacements', () => {
    expect(useUploadStore.getState().pendingReplacements).toEqual([]);
  });

  it('setPendingReplacements stores replacements', () => {
    useUploadStore.getState().setPendingReplacements([testReplacement]);

    const state = useUploadStore.getState();
    expect(state.pendingReplacements).toHaveLength(1);
    expect(state.pendingReplacements[0].fileName).toBe('test.txt');
    expect(state.pendingReplacements[0].fileId).toBe('file-123');
    expect(state.pendingReplacements[0].encryptedData.cid).toBe('bafytest123');
    expect(state.pendingReplacements[0].encryptedData.encryptionMode).toBe('GCM');
  });

  it('setPendingReplacements handles multiple items', () => {
    const second: PendingReplacement = {
      ...testReplacement,
      fileName: 'doc.pdf',
      fileId: 'file-456',
      encryptedData: { ...testReplacement.encryptedData, cid: 'bafytest456', size: 2048 },
    };
    useUploadStore.getState().setPendingReplacements([testReplacement, second]);

    expect(useUploadStore.getState().pendingReplacements).toHaveLength(2);
    expect(useUploadStore.getState().pendingReplacements[1].fileName).toBe('doc.pdf');
  });

  it('clearPendingReplacements empties the array', () => {
    useUploadStore.getState().setPendingReplacements([testReplacement]);
    expect(useUploadStore.getState().pendingReplacements).toHaveLength(1);

    useUploadStore.getState().clearPendingReplacements();
    expect(useUploadStore.getState().pendingReplacements).toEqual([]);
  });

  it('reset clears pendingReplacements', () => {
    useUploadStore.getState().setPendingReplacements([testReplacement]);
    expect(useUploadStore.getState().pendingReplacements).toHaveLength(1);

    useUploadStore.getState().reset();
    expect(useUploadStore.getState().pendingReplacements).toEqual([]);
  });

  it('setPendingReplacements replaces previous items', () => {
    useUploadStore.getState().setPendingReplacements([testReplacement]);

    const replacement2: PendingReplacement = {
      ...testReplacement,
      fileName: 'other.txt',
      fileId: 'file-789',
    };
    useUploadStore.getState().setPendingReplacements([replacement2]);

    const state = useUploadStore.getState();
    expect(state.pendingReplacements).toHaveLength(1);
    expect(state.pendingReplacements[0].fileName).toBe('other.txt');
  });
});
