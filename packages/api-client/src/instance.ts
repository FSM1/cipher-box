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
};

/**
 * Create a configured axios instance for CipherBox API calls.
 * No Zustand, no import.meta.env -- all config injected by consumer.
 */
export function createAxiosInstance(config: ApiClientConfig): AxiosInstance {
  const instance = axios.create({ baseURL: config.baseUrl });
  instance.interceptors.request.use(async (reqConfig) => {
    const token = await config.getAccessToken();
    if (token) {
      reqConfig.headers.Authorization = `Bearer ${token}`;
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

function getCachedInstance(): AxiosInstance {
  if (!_instance) {
    const clientConfig = getApiClientConfig();
    _instance = axios.create({ baseURL: clientConfig.baseUrl });
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
