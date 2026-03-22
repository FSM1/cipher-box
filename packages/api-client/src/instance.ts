import axios, {
  type AxiosInstance,
  type AxiosRequestConfig,
  type AxiosError,
  type AxiosProgressEvent,
  type CancelToken,
} from 'axios';

export type ApiClientConfig = {
  /** Base URL for the CipherBox API (e.g., "http://localhost:3000") */
  baseUrl: string;
  /** Returns a valid access token. Consumer owns refresh logic. */
  getAccessToken: () => Promise<string>;
  /** Called on 401 response to obtain a new access token. If provided, the failed request is retried once with the new token. */
  refreshAccessToken?: () => Promise<string>;
  /** Send cookies cross-origin (needed for HTTP-only refresh token cookie in web). */
  withCredentials?: boolean;
  /** Called when token refresh fails (e.g., clear stores, redirect to login). */
  onRefreshFailure?: () => void;
  /** Extra headers sent with every request (e.g., throttle bypass for testing). */
  defaultHeaders?: Record<string, string>;
};

/**
 * Create a configured axios instance for CipherBox API calls.
 * No Zustand, no import.meta.env -- all config injected by consumer.
 */
export function createAxiosInstance(config: ApiClientConfig): AxiosInstance {
  const instance = axios.create({
    baseURL: config.baseUrl,
    withCredentials: config.withCredentials ?? false,
    headers: config.defaultHeaders,
  });
  instance.interceptors.request.use(async (reqConfig) => {
    const token = await config.getAccessToken();
    if (token) {
      reqConfig.headers.set('Authorization', `Bearer ${token}`);
    }
    return reqConfig;
  });
  return instance;
}

/**
 * Custom instance function for orval-generated code.
 * Matches the signature orval expects from a mutator.
 * The consumer must call setApiClientConfig() before using generated functions.
 */
let _config: ApiClientConfig | null = null;
let _instance: AxiosInstance | null = null;

export function setApiClientConfig(config: ApiClientConfig): void {
  _config = config;
  _instance = null; // Reset cached instance when config changes
}

export function getApiClientConfig(): ApiClientConfig {
  if (!_config) throw new Error('API client not configured. Call setApiClientConfig() first.');
  return _config;
}

// Shared refresh promise eliminates race condition where multiple concurrent
// 401 responses each trigger their own refresh before the first completes.
let _refreshPromise: Promise<string> | null = null;

function getCachedInstance(): AxiosInstance {
  if (!_instance) {
    const clientConfig = getApiClientConfig();
    _instance = axios.create({
      baseURL: clientConfig.baseUrl,
      withCredentials: clientConfig.withCredentials ?? false,
      headers: clientConfig.defaultHeaders,
    });

    // 401 response interceptor: refresh token and retry once
    if (clientConfig.refreshAccessToken) {
      const refreshFn = clientConfig.refreshAccessToken;
      const onFailure = clientConfig.onRefreshFailure;

      _instance.interceptors.response.use(
        (response) => response,
        async (error: AxiosError) => {
          const originalRequest = error.config as
            | (AxiosRequestConfig & { _retry?: boolean })
            | undefined;
          if (!originalRequest) throw error;

          // Don't retry refresh endpoint to avoid infinite loop
          const isRefreshRequest = originalRequest.url?.includes('/auth/refresh');

          if (error.response?.status === 401 && !originalRequest._retry && !isRefreshRequest) {
            originalRequest._retry = true;

            if (!_refreshPromise) {
              // First 401 handler: create the refresh promise synchronously
              _refreshPromise = refreshFn()
                .catch((refreshError) => {
                  onFailure?.();
                  throw refreshError;
                })
                .finally(() => {
                  _refreshPromise = null;
                });
            }

            // All concurrent 401 handlers await the same promise.
            const token = await _refreshPromise;
            originalRequest.headers = originalRequest.headers ?? {};
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
            return getCachedInstance().request(originalRequest);
          }

          throw error;
        }
      );
    }
  }
  return _instance;
}

export const customInstance = async <T>(
  config: AxiosRequestConfig,
  options?: AxiosRequestConfig
): Promise<T> => {
  const clientConfig = getApiClientConfig();
  const token = await clientConfig.getAccessToken();
  const instance = getCachedInstance();

  const response = await instance.request<T>({
    ...config,
    ...options,
    headers: {
      ...config.headers,
      ...options?.headers,
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  return response.data;
};

export default customInstance;

export type ErrorType<Error> = AxiosError<Error>;
export type BodyType<BodyData> = BodyData;

// Re-export axios types that consumers need for IPFS upload (progress, cancel)
export type { AxiosInstance, AxiosProgressEvent, CancelToken };
export { default as axios } from 'axios';
