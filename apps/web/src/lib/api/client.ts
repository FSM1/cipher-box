import axios from 'axios';
import { useAuthStore } from '../../stores/auth.store';
import { useVaultStore } from '../../stores/vault.store';
import { useFolderStore } from '../../stores/folder.store';

// Shared refresh promise eliminates race condition where multiple concurrent
// 401 responses each trigger their own POST /auth/refresh before the boolean
// flag could be set. The promise is assigned synchronously before any await,
// so all concurrent 401 handlers see it immediately and share the same refresh.
let refreshPromise: Promise<string> | null = null;

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3000',
  withCredentials: true, // For HTTP-only refresh token cookie
});

// Request interceptor: Add access token to headers
apiClient.interceptors.request.use((config) => {
  const accessToken = useAuthStore.getState().accessToken;
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// Response interceptor: Handle 401 and token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Don't retry refresh endpoint to avoid infinite loop
    const isRefreshRequest = originalRequest?.url?.includes('/auth/refresh');

    // Only handle 401 errors, and only retry once (but never retry refresh endpoint)
    if (error.response?.status === 401 && !originalRequest._retry && !isRefreshRequest) {
      originalRequest._retry = true;

      // If a refresh is already in flight, all concurrent 401 handlers
      // await the same promise instead of firing duplicate refresh requests.
      if (refreshPromise) {
        const token = await refreshPromise;
        originalRequest.headers.Authorization = `Bearer ${token}`;
        return apiClient(originalRequest);
      }

      // First 401 handler: create the refresh promise synchronously (before any await)
      // so subsequent 401 handlers in the same microtask see it immediately.
      refreshPromise = apiClient
        .post<{ accessToken: string }>('/auth/refresh')
        .then((response) => {
          const { accessToken } = response.data;
          useAuthStore.getState().setAccessToken(accessToken);
          return accessToken;
        })
        .catch((refreshError) => {
          // [SECURITY: HIGH-03] Clear all stores including crypto keys on token refresh failure
          useFolderStore.getState().clearFolders();
          useVaultStore.getState().clearVaultKeys();
          useAuthStore.getState().logout();
          // Redirect to login will be handled by route guard
          throw refreshError;
        })
        .finally(() => {
          refreshPromise = null;
        });

      const token = await refreshPromise;
      originalRequest.headers.Authorization = `Bearer ${token}`;
      return apiClient(originalRequest);
    }

    throw error;
  }
);
