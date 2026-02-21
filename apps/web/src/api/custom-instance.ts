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
  responseType?: 'json' | 'blob' | 'text';
}): Promise<T> => {
  const { url, method, params, data, headers, signal, responseType = 'json' } = config;

  // Get auth token from store
  const accessToken = useAuthStore.getState().accessToken;

  const queryString = params ? '?' + new URLSearchParams(params).toString() : '';

  const response = await fetch(`${BASE_URL}${url}${queryString}`, {
    method,
    headers: {
      // Only set Content-Type for JSON requests with body
      ...(data && responseType === 'json' ? { 'Content-Type': 'application/json' } : {}),
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...headers,
    },
    body: data ? JSON.stringify(data) : undefined,
    signal,
  });

  if (!response.ok) {
    const err = new Error(`HTTP error! status: ${response.status}`);
    (err as Error & { status: number }).status = response.status;
    throw err;
  }

  // Return appropriate response type
  if (responseType === 'blob') {
    return response.blob() as Promise<T>;
  } else if (responseType === 'text') {
    return response.text() as Promise<T>;
  }
  // Responses with no body (204 No Content, 201 with void return, etc.)
  // Read as text first to avoid JSON parse error on empty bodies
  const text = await response.text();
  if (!text) {
    return undefined as T;
  }
  return JSON.parse(text);
};

export default customInstance;
