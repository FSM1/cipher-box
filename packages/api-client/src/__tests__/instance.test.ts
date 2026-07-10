import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import { setApiClientConfig, customInstance } from '../instance';

describe('instance – 401 refresh interceptor', () => {
  let mockAxios: MockAdapter;
  let getAccessToken: ReturnType<typeof vi.fn>;
  let refreshAccessToken: ReturnType<typeof vi.fn>;
  let onRefreshFailure: ReturnType<typeof vi.fn>;
  const origCreate = axios.create.bind(axios);
  let createSpy: MockInstance<typeof axios.create>;

  beforeEach(async () => {
    getAccessToken = vi.fn().mockResolvedValue('initial-token');
    refreshAccessToken = vi.fn().mockResolvedValue('refreshed-token');
    onRefreshFailure = vi.fn();

    createSpy = vi.spyOn(axios, 'create').mockImplementation((config) => {
      const instance = origCreate(config);
      mockAxios = new MockAdapter(instance);
      return instance;
    });

    setApiClientConfig({
      baseUrl: 'http://test-api',
      getAccessToken,
      refreshAccessToken,
      onRefreshFailure,
      withCredentials: true,
    });

    // Trigger instance creation so mockAxios is available for all tests.
    // This warm-up request will fail because no routes are mocked yet — that's fine.
    try {
      mockAxios?.onGet('/__warmup').reply(200, {});
    } catch {
      // mockAxios not yet set — expected on first call
    }
    try {
      await customInstance({ url: '/__warmup', method: 'GET' });
    } catch {
      // May fail — we just need the side effect of creating the instance
    }
    // Now mockAxios is set. Reset it for the actual test.
    mockAxios.reset();
  });

  afterEach(() => {
    createSpy.mockRestore();
  });

  it('retries with refreshed token on 401', async () => {
    let callCount = 0;
    mockAxios.onGet('/test').reply(() => {
      callCount++;
      if (callCount === 1) return [401, 'Unauthorized'];
      return [200, { ok: true }];
    });

    const result = await customInstance({ url: '/test', method: 'GET' });

    expect(result).toEqual({ ok: true });
    expect(refreshAccessToken).toHaveBeenCalledOnce();
    expect(callCount).toBe(2);
  });

  it('does not retry refresh endpoint to avoid infinite loop', async () => {
    mockAxios.onPost('/auth/refresh').reply(401);

    await expect(customInstance({ url: '/auth/refresh', method: 'POST' })).rejects.toThrow();

    expect(refreshAccessToken).not.toHaveBeenCalled();
  });

  it('calls onRefreshFailure when refresh rejects', async () => {
    refreshAccessToken.mockRejectedValue(new Error('refresh failed'));
    mockAxios.onGet('/test').reply(401);

    await expect(customInstance({ url: '/test', method: 'GET' })).rejects.toThrow();

    expect(onRefreshFailure).toHaveBeenCalledOnce();
  });

  it('deduplicates concurrent refresh requests', async () => {
    let refreshCallCount = 0;
    refreshAccessToken.mockImplementation(
      () =>
        new Promise((resolve) => {
          refreshCallCount++;
          setTimeout(() => resolve('refreshed-token'), 50);
        })
    );

    const callCounts: Record<string, number> = {};
    mockAxios.onGet('/a').reply(() => {
      callCounts['/a'] = (callCounts['/a'] ?? 0) + 1;
      return callCounts['/a'] === 1 ? [401, 'Unauthorized'] : [200, { id: 'a' }];
    });
    mockAxios.onGet('/b').reply(() => {
      callCounts['/b'] = (callCounts['/b'] ?? 0) + 1;
      return callCounts['/b'] === 1 ? [401, 'Unauthorized'] : [200, { id: 'b' }];
    });

    const [resultA, resultB] = await Promise.all([
      customInstance({ url: '/a', method: 'GET' }),
      customInstance({ url: '/b', method: 'GET' }),
    ]);

    expect(resultA).toEqual({ id: 'a' });
    expect(resultB).toEqual({ id: 'b' });
    expect(refreshCallCount).toBe(1);
  });

  it('creates instance with withCredentials from config', () => {
    // Instance was already created in beforeEach
    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        baseURL: 'http://test-api',
        withCredentials: true,
      })
    );
  });
});
