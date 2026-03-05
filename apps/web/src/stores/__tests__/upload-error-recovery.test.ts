/**
 * Upload Error Recovery Tests
 *
 * Verifies:
 * 1. Upload store transitions to 'error' when addFiles fails after registering
 * 2. Orphaned IPFS pins are cleaned up when registration fails after successful upload
 * 3. Quota is refreshed after orphan cleanup
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useUploadStore } from '../upload.store';
import type { PendingReplacement } from '../upload.store';

/**
 * Simulates the catch-block error recovery logic from UploadZone/EmptyState.
 * Extracted here so we can test all branches without fighting TypeScript narrowing.
 */
function simulateErrorRecovery(
  errorMessage: string,
  uploadedFiles: { cid: string }[] | undefined,
  unpinFn: (cid: string) => Promise<void>,
  fetchQuotaFn: () => Promise<void>
) {
  if (errorMessage !== 'Upload cancelled by user') {
    useUploadStore.getState().setError(errorMessage);

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

  describe('setError transitions store out of registering', () => {
    it('should transition from registering to error state', () => {
      useUploadStore.getState().startUpload(2);
      useUploadStore.getState().setEncrypting('file1.txt');
      useUploadStore.getState().setUploading('file1.txt', 100);
      useUploadStore.getState().fileComplete();
      useUploadStore.getState().setRegistering();

      expect(useUploadStore.getState().status).toBe('registering');

      useUploadStore.getState().setError('Duplicate filename');

      const state = useUploadStore.getState();
      expect(state.status).toBe('error');
      expect(state.error).toBe('Duplicate filename');
      expect(state.currentFile).toBeNull();
    });

    it('should allow reset after error state', () => {
      useUploadStore.getState().startUpload(1);
      useUploadStore.getState().setRegistering();
      useUploadStore.getState().setError('Network error');

      expect(useUploadStore.getState().status).toBe('error');

      useUploadStore.getState().reset();

      const state = useUploadStore.getState();
      expect(state.status).toBe('idle');
      expect(state.error).toBeNull();
      expect(state.progress).toBe(0);
      expect(state.totalFiles).toBe(0);
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

    const uploadedFiles = [{ cid: 'QmAAA' }, { cid: 'QmBBB' }, { cid: 'QmCCC' }];

    simulateErrorRecovery(
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
    expect(useUploadStore.getState().status).toBe('error');
  });

  it('should NOT unpin when upload itself failed (uploadedFiles is undefined)', () => {
    const mockUnpin = vi.fn();
    const mockFetchQuota = vi.fn();

    simulateErrorRecovery('Encryption failed', undefined, mockUnpin, mockFetchQuota);

    expect(mockUnpin).not.toHaveBeenCalled();
    expect(mockFetchQuota).not.toHaveBeenCalled();
    expect(useUploadStore.getState().status).toBe('error');
  });

  it('should NOT unpin or set error when user cancels upload', () => {
    const mockUnpin = vi.fn();
    const mockFetchQuota = vi.fn();

    simulateErrorRecovery(
      'Upload cancelled by user',
      [{ cid: 'QmAAA' }],
      mockUnpin,
      mockFetchQuota
    );

    expect(mockUnpin).not.toHaveBeenCalled();
    expect(mockFetchQuota).not.toHaveBeenCalled();
    expect(useUploadStore.getState().status).toBe('idle');
  });

  it('should handle unpin failures gracefully (fire-and-forget)', () => {
    const mockUnpin = vi.fn().mockRejectedValue(new Error('Unpin failed'));
    const mockFetchQuota = vi.fn().mockResolvedValue(undefined);

    simulateErrorRecovery('Registration failed', [{ cid: 'QmFAIL' }], mockUnpin, mockFetchQuota);

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
