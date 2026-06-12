import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../lib/api/ipfs', () => ({
  unpinFromIpfs: vi.fn().mockResolvedValue(undefined),
}));

const mockRemoveUsage = vi.fn();
const mockFetchQuota = vi.fn().mockResolvedValue(undefined);

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
    mockFetchQuota.mockResolvedValue(undefined);
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
    });

    await deleteFile('bafytest123', 1024);

    expect(callOrder[0]).toBe('unpinFromIpfs');
    expect(callOrder[1]).toBe('removeUsage');
    expect(mockFetchQuota).toHaveBeenCalledOnce();
  });

  it('resolves even when fetchQuota rejects, and logs a warning', async () => {
    const fetchError = new Error('quota endpoint unreachable');
    mockFetchQuota.mockRejectedValueOnce(fetchError);

    await expect(deleteFile('bafytest456', 2048)).resolves.toBeUndefined();

    // Give the fire-and-forget microtask a chance to settle
    await Promise.resolve();

    expect(logger.warn).toHaveBeenCalledWith('quota reconcile failed', fetchError);
  });

  it('invokes both removeUsage and fetchQuota before resolving', async () => {
    await deleteFile('bafytest789', 512);

    expect(mockRemoveUsage).toHaveBeenCalledWith(512);
    expect(mockFetchQuota).toHaveBeenCalledOnce();
  });
});
