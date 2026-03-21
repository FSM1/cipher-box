/**
 * SDK Context -- injected configuration for all sdk-core functions.
 * Replaces the Zustand store access pattern (useAuthStore.getState()).
 */
export type SdkContext = {
  /** Base URL for the CipherBox API (e.g., "http://localhost:3000") */
  apiUrl: string;
  /** Returns a valid access token. Consumer owns refresh logic. */
  getAccessToken: () => Promise<string>;
};

/**
 * TEE key configuration, passed explicitly instead of read from auth store.
 */
export type TeeKeys = {
  currentPublicKey: string;
  currentEpoch: number;
  previousPublicKey?: string | null;
  previousEpoch?: number | null;
};

/**
 * Result of an IPFS upload operation.
 */
export type IpfsAddResult = {
  cid: string;
  size: number;
  recorded: boolean;
};

/**
 * Progress callback for upload/download operations.
 */
export type ProgressCallback = (percent: number) => void;
export type DownloadProgressCallback = (loaded: number, total: number) => void;
