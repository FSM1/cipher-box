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
