/**
 * Early API client configuration.
 *
 * Imported at module scope (before any auth API calls) so that
 * @cipherbox/api-client's customInstance is ready when authApi.*
 * or any generated function is called.
 *
 * getAccessToken reads from Zustand store (initially null, populated after login).
 * refreshAccessToken calls the refresh endpoint using HTTP-only cookie.
 * onRefreshFailure clears all user stores (same behaviour as the old client.ts interceptor).
 */
import { setApiClientConfig, authControllerRefresh } from '@cipherbox/api-client';
import { useAuthStore } from '../stores/auth.store';

const apiUrl =
  import.meta.env.VITE_API_URL ||
  (typeof window !== 'undefined' ? `${window.location.origin}/api` : '/api');

setApiClientConfig({
  baseUrl: apiUrl,
  getAccessToken: async () => useAuthStore.getState().accessToken || '',
  withCredentials: true,
  refreshAccessToken: async () => {
    // DesktopRefreshDto.refreshToken is optional -- web uses HTTP-only cookie instead
    const response = await authControllerRefresh({});
    const newToken = response.accessToken;
    const store = useAuthStore.getState();
    store.setAccessToken(newToken);
    store.setAuthenticated();
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
});

export { apiUrl };
