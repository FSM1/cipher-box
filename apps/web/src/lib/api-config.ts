/**
 * API client configuration — single shared axios instance.
 *
 * Creates one axios instance with auth interceptors (token injection + 401 refresh)
 * and registers it as both the orval singleton and the exported `apiAxios` instance.
 *
 * The same instance is used by:
 * - Orval-generated functions (via singleton path in customInstance)
 * - CipherBoxClient (via CipherBoxClientConfig.axiosInstance)
 * - sdk-core IPFS operations (via SdkContext.axiosInstance)
 *
 * This eliminates the dual-path architecture where the singleton and SDK client
 * had separate axios instances with potentially divergent configuration.
 */
import {
  createAxiosInstance,
  setApiClientConfig,
  authControllerRefresh,
} from '@cipherbox/api-client';
import { useAuthStore } from '../stores/auth.store';

const apiUrl =
  import.meta.env.VITE_API_URL ||
  (typeof window !== 'undefined' ? `${window.location.origin}/api` : '/api');

const apiConfig = {
  baseUrl: apiUrl,
  getAccessToken: async () => useAuthStore.getState().accessToken || '',
  withCredentials: true,
  refreshAccessToken: async () => {
    // Uses the same apiAxios instance (captured via closure).
    // Safe because apiAxios is assigned synchronously before any 401 can occur.
    const response = await authControllerRefresh({}, { _axiosInstance: apiAxios });
    const newToken = response.accessToken;
    useAuthStore.getState().setAccessToken(newToken);
    return newToken;
  },
  onRefreshFailure: () => {
    // Dynamic import to avoid circular dependency at module load time
    import('../lib/clear-user-stores')
      .then(({ clearAllUserStores }) => {
        clearAllUserStores();
      })
      .catch(() => {
        // Chunk load failed — force reload to clear stale session state
        window.location.reload();
      });
  },
};

/** Shared axios instance used by the entire web app. */
export const apiAxios = createAxiosInstance(apiConfig);

// Register as the orval singleton so generated functions work without
// explicit _axiosInstance. The same instance is reused (no duplicate creation).
setApiClientConfig(apiConfig, apiAxios);

export { apiUrl };
