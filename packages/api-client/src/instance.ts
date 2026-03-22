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
 *
 * Includes:
 * - Request interceptor: injects Bearer token from getAccessToken()
 * - Response interceptor (optional): 401 refresh + retry when refreshAccessToken is provided
 */
export function createAxiosInstance(config: ApiClientConfig): AxiosInstance {
  const instance = axios.create({
    baseURL: config.baseUrl,
    withCredentials: config.withCredentials ?? false,
    headers: config.defaultHeaders,
  });

  // Request interceptor: inject auth token
  instance.interceptors.request.use(async (reqConfig) => {
    const token = await config.getAccessToken();
    if (token) {
      reqConfig.headers.set('Authorization', `Bearer ${token}`);
    }
    return reqConfig;
  });

  // Response interceptor: 401 refresh + retry (optional)
  if (config.refreshAccessToken) {
    const refreshFn = config.refreshAccessToken;
    const onFailure = config.onRefreshFailure;
    let refreshPromise: Promise<string> | null = null;

    instance.interceptors.response.use(
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

          if (!refreshPromise) {
            refreshPromise = refreshFn()
              .catch((refreshError) => {
                onFailure?.();
                throw refreshError;
              })
              .finally(() => {
                refreshPromise = null;
              });
          }

          // All concurrent 401 handlers await the same promise
          const token = await refreshPromise;
          originalRequest.headers = originalRequest.headers ?? {};
          originalRequest.headers['Authorization'] = `Bearer ${token}`;
          return instance.request(originalRequest);
        }

        throw error;
      }
    );
  }

  return instance;
}

/**
 * Singleton configuration for orval-generated code.
 * The consumer must call setApiClientConfig() before using generated functions
 * without passing _axiosInstance explicitly.
 */
let _config: ApiClientConfig | null = null;
let _instance: AxiosInstance | null = null;

/**
 * Configure the module-level singleton used by orval-generated functions.
 *
 * @param config - API client configuration
 * @param instance - Optional pre-built axios instance. When provided,
 *   getCachedInstance() returns it directly instead of creating a new one.
 *   Use this to share a single instance between the singleton path and
 *   instance-scoped consumers (e.g., CipherBoxClient).
 */
export function setApiClientConfig(config: ApiClientConfig, instance?: AxiosInstance): void {
  _config = config;
  _instance = instance ?? null;
}

export function getApiClientConfig(): ApiClientConfig {
  if (!_config) throw new Error('API client not configured. Call setApiClientConfig() first.');
  return _config;
}

function getCachedInstance(): AxiosInstance {
  if (!_instance) {
    _instance = createAxiosInstance(getApiClientConfig());
  }
  return _instance;
}

export const customInstance = async <T>(
  config: AxiosRequestConfig,
  options?: AxiosRequestConfig & { _axiosInstance?: AxiosInstance }
): Promise<T> => {
  const { _axiosInstance, ...restOptions } = options ?? {};

  if (_axiosInstance) {
    // Instance-scoped path: the provided instance has its own interceptors for auth
    const response = await _axiosInstance.request<T>({
      ...config,
      ...restOptions,
      headers: {
        ...config.headers,
        ...restOptions.headers,
      },
    });
    return response.data;
  }

  // Singleton path: uses getCachedInstance() which has its own request interceptor
  const instance = getCachedInstance();

  const response = await instance.request<T>({
    ...config,
    ...restOptions,
    headers: {
      ...config.headers,
      ...restOptions.headers,
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
