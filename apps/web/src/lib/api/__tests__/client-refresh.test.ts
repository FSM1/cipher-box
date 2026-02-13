/**
 * Auth Token Refresh Tests
 *
 * Verifies the shared-Promise deduplication pattern eliminates the race condition
 * where multiple concurrent 401 responses each triggered separate POST /auth/refresh calls.
 */

import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import MockAdapter from 'axios-mock-adapter';

// Mock stores before importing client
vi.mock('../../../stores/auth.store', () => ({
  useAuthStore: {
    getState: vi.fn(() => ({
      accessToken: 'expired-token',
      setAccessToken: vi.fn(),
      logout: vi.fn(),
    })),
  },
}));

vi.mock('../../../stores/vault.store', () => ({
  useVaultStore: {
    getState: vi.fn(() => ({
      clearVaultKeys: vi.fn(),
    })),
  },
}));

vi.mock('../../../stores/folder.store', () => ({
  useFolderStore: {
    getState: vi.fn(() => ({
      clearFolders: vi.fn(),
    })),
  },
}));

import { apiClient } from '../client';
import { useAuthStore } from '../../../stores/auth.store';
import { useVaultStore } from '../../../stores/vault.store';
import { useFolderStore } from '../../../stores/folder.store';

describe('Auth Token Refresh - Race Condition Fix', () => {
  let mock: MockAdapter;
  let mockSetAccessToken: Mock;
  let mockLogout: Mock;
  let mockClearVaultKeys: Mock;
  let mockClearFolders: Mock;

  beforeEach(() => {
    mock = new MockAdapter(apiClient);
    mockSetAccessToken = vi.fn();
    mockLogout = vi.fn();
    mockClearVaultKeys = vi.fn();
    mockClearFolders = vi.fn();

    (useAuthStore.getState as Mock).mockReturnValue({
      accessToken: 'expired-token',
      setAccessToken: mockSetAccessToken,
      logout: mockLogout,
    });

    (useVaultStore.getState as Mock).mockReturnValue({
      clearVaultKeys: mockClearVaultKeys,
    });

    (useFolderStore.getState as Mock).mockReturnValue({
      clearFolders: mockClearFolders,
    });
  });

  afterEach(() => {
    mock.restore();
  });

  it('should deduplicate concurrent 401s into a single refresh call', async () => {
    let refreshCallCount = 0;

    // Each endpoint returns 401 once, then 200 on retry
    mock.onGet('/api/data1').replyOnce(401).onGet('/api/data1').reply(200, { data: 'one' });
    mock.onGet('/api/data2').replyOnce(401).onGet('/api/data2').reply(200, { data: 'two' });
    mock.onGet('/api/data3').replyOnce(401).onGet('/api/data3').reply(200, { data: 'three' });

    mock.onPost('/auth/refresh').reply(() => {
      refreshCallCount++;
      return [200, { accessToken: 'new-token' }];
    });

    const [r1, r2, r3] = await Promise.all([
      apiClient.get('/api/data1'),
      apiClient.get('/api/data2'),
      apiClient.get('/api/data3'),
    ]);

    expect(r1.data).toEqual({ data: 'one' });
    expect(r2.data).toEqual({ data: 'two' });
    expect(r3.data).toEqual({ data: 'three' });

    // Critical assertion: only ONE refresh call
    expect(refreshCallCount).toBe(1);
    expect(mockSetAccessToken).toHaveBeenCalledWith('new-token');
  });

  it('should retry the original request with the new token after refresh', async () => {
    mock.onGet('/api/protected').replyOnce(401).onGet('/api/protected').reply(200, { ok: true });
    mock.onPost('/auth/refresh').reply(200, { accessToken: 'fresh-token' });

    const response = await apiClient.get('/api/protected');

    expect(response.data).toEqual({ ok: true });
    expect(mockSetAccessToken).toHaveBeenCalledWith('fresh-token');
  });

  it('should clear all stores on refresh failure (SECURITY HIGH-03)', async () => {
    mock.onGet('/api/protected').replyOnce(401);
    mock.onPost('/auth/refresh').reply(401);

    await expect(apiClient.get('/api/protected')).rejects.toThrow();

    expect(mockClearFolders).toHaveBeenCalled();
    expect(mockClearVaultKeys).toHaveBeenCalled();
    expect(mockLogout).toHaveBeenCalled();
  });

  it('should not retry the refresh endpoint itself (infinite loop prevention)', async () => {
    mock.onPost('/auth/refresh').reply(401);

    await expect(apiClient.post('/auth/refresh')).rejects.toThrow();

    // Only one call — no retry loop
    expect(mock.history.post.filter((r) => r.url === '/auth/refresh')).toHaveLength(1);
  });

  it('should reject all queued requests if refresh fails', async () => {
    mock.onGet('/api/a').reply(401);
    mock.onGet('/api/b').reply(401);
    mock.onPost('/auth/refresh').reply(401);

    const results = await Promise.allSettled([apiClient.get('/api/a'), apiClient.get('/api/b')]);

    expect(results[0].status).toBe('rejected');
    expect(results[1].status).toBe('rejected');
  });
});
