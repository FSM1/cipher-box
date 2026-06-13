import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../lib/api/ipfs', () => ({
  unpinFromIpfs: vi.fn().mockResolvedValue(undefined),
}));

const mockRemoveUsage = vi.fn();
const mockFetchQuota = vi.fn().mockResolvedValue(true);

vi.mock('../stores/quota.store', () => ({
  useQuotaStore: {
    getState: vi.fn(() => ({
      removeUsage: mockRemoveUsage,
      fetchQuota: mockFetchQuota,
    })),
  },
}));

vi.mock('../lib/logger', () => ({
  logger: {
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

import { unpinFromIpfs } from '../lib/api/ipfs';
import { logger } from '../lib/logger';
import { deleteFile } from './delete.service';

describe('deleteFile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchQuota.mockResolvedValue(true);
  });

  it('calls unpinFromIpfs, then removeUsage, then fetchQuota in order', async () => {
    const callOrder: string[] = [];
    vi.mocked(unpinFromIpfs).mockImplementationOnce(async () => {
      callOrder.push('unpinFromIpfs');
    });
    mockRemoveUsage.mockImplementationOnce(() => {
      callOrder.push('removeUsage');
    });
    mockFetchQuota.mockImplementationOnce(async () => {
      callOrder.push('fetchQuota');
      return true;
    });

    await deleteFile('bafytest123', 1024);

    expect(callOrder[0]).toBe('unpinFromIpfs');
    expect(callOrder[1]).toBe('removeUsage');
    expect(mockFetchQuota).toHaveBeenCalledOnce();
  });

  it('resolves and logs a warning when fetchQuota reports failure', async () => {
    mockFetchQuota.mockResolvedValueOnce(false);

    await expect(deleteFile('bafytest456', 2048)).resolves.toBeUndefined();

    // Give the fire-and-forget microtask a chance to settle
    await Promise.resolve();

    expect(logger.warn).toHaveBeenCalledWith('quota reconcile failed');
  });

  it('invokes both removeUsage and fetchQuota before resolving', async () => {
    await deleteFile('bafytest789', 512);

    expect(mockRemoveUsage).toHaveBeenCalledWith(512);
    expect(mockFetchQuota).toHaveBeenCalledOnce();
  });
});
