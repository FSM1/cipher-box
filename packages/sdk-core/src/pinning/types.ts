/** Result of a pin operation */
export type PinResult = {
  cid: string;
  size: number;
};

/** Status of a pin */
export type PinStatus = {
  cid: string;
  status: 'queued' | 'pinning' | 'pinned' | 'failed';
};

/** Abstract pinning provider -- implemented by KuboProvider and PsaProvider */
export interface PinningProvider {
  /** Upload and pin data, returning CID and size */
  pin(data: Uint8Array, name?: string): Promise<PinResult>;
  /** Remove a pin by CID */
  unpin(cid: string): Promise<void>;
  /** Check pin status by CID */
  status(cid: string): Promise<PinStatus>;
  /** Fetch pinned content by CID */
  get(cid: string): Promise<Uint8Array>;
}

/** User-selectable pinning mode */
export type PinningMode = 'cipherbox' | 'external' | 'dual';

/** Configuration for an external IPFS provider */
export type ExternalProviderConfig = {
  endpoint: string;
  authToken: string;
  protocol: 'psa' | 'kubo' | 'pinata';
  providerName?: string;
};

/** Result of a connection test */
export type ConnectionTestResult = {
  success: boolean;
  protocol?: 'kubo' | 'psa' | 'pinata';
  version?: string;
  latencyMs: number;
  error?: string;
  corsError?: boolean;
  corsInstructions?: string;
};
