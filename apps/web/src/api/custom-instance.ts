import { useAuthStore } from '../stores/auth.store';

// Use VITE_API_URL if set, otherwise default to same-origin /api path for deployed environments
const BASE_URL =
  import.meta.env.VITE_API_URL ||
  (typeof window !== 'undefined' ? `${window.location.origin}/api` : '/api');

export const customInstance = async <T>(config: {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  params?: Record<string, string>;
  data?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}): Promise<T> => {
  const { url, method, params, data, headers, signal } = config;

  // Get auth token from store
  const accessToken = useAuthStore.getState().accessToken;

  const queryString = params ? '?' + new URLSearchParams(params).toString() : '';

  const response = await fetch(`${BASE_URL}${url}${queryString}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...headers,
    },
    body: data ? JSON.stringify(data) : undefined,
    signal,
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return response.json();
};

export default customInstance;
