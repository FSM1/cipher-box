import type { PinningProvider, PinResult, PinStatus, ProviderOptions, FetchFn } from './types';

/** Default timeout for all Kubo RPC requests — generous for large file pins */
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * PinningProvider implementation for Kubo RPC API (/api/v0/*).
 *
 * Talks directly to a Kubo node's HTTP API. Suitable for self-hosted
 * Kubo nodes or any IPFS node exposing the Kubo-compatible RPC interface.
 */
export class KuboProvider implements PinningProvider {
  private readonly endpoint: string;
  private readonly authToken?: string;
  private readonly fetchFn: FetchFn;
  private readonly timeoutMs: number;

  constructor(endpoint: string, authToken?: string, options?: ProviderOptions) {
    // Normalize: strip trailing slash
    this.endpoint = endpoint.replace(/\/+$/, '');
    this.authToken = authToken;
    this.fetchFn = options?.fetchFn ?? globalThis.fetch;
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /**
   * Upload and pin data to the Kubo node.
   * Uses /api/v0/add with pin=true and cid-version=1 for CIDv1.
   */
  async pin(data: Uint8Array, _name?: string): Promise<PinResult> {
    const url = `${this.endpoint}/api/v0/add?pin=true&cid-version=1`;
    const formData = new FormData();
    // Pass typed array directly to Blob (never use .buffer to avoid offset issues)
    const blob = new Blob([data as BlobPart], { type: 'application/octet-stream' });
    formData.append('file', blob);

    const response = await this.fetchFn(url, {
      method: 'POST',
      body: formData,
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Kubo add failed: ${response.status} - ${errorText}`);
    }

    // Kubo returns ndjson; for a single file, parse the first (only) line
    const text = await response.text();
    const result = JSON.parse(text) as { Hash: string; Size: string };
    return {
      cid: result.Hash,
      size: parseInt(result.Size, 10),
    };
  }

  /**
   * Remove a pin by CID.
   * Ignores "not pinned" errors for idempotency.
   */
  async unpin(cid: string): Promise<void> {
    const url = `${this.endpoint}/api/v0/pin/rm?arg=${encodeURIComponent(cid)}`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!response.ok) {
      const errorText = await response.text();
      // "not pinned" means already unpinned -- treat as success (idempotent)
      if (errorText.toLowerCase().includes('not pinned')) {
        return;
      }
      throw new Error(`Kubo unpin failed: ${response.status} - ${errorText}`);
    }
  }

  /**
   * Check pin status by CID.
   * Returns 'pinned' on success, 'failed' if the CID is not pinned.
   */
  async status(cid: string): Promise<PinStatus> {
    const url = `${this.endpoint}/api/v0/pin/ls?arg=${encodeURIComponent(cid)}`;

    try {
      const response = await this.fetchFn(url, {
        method: 'POST',
        headers: this.buildHeaders(),
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (!response.ok) {
        return { cid, status: 'failed' };
      }

      return { cid, status: 'pinned' };
    } catch {
      return { cid, status: 'failed' };
    }
  }

  /**
   * Fetch pinned content by CID.
   * Returns the raw bytes of the content.
   */
  async get(cid: string): Promise<Uint8Array> {
    const url = `${this.endpoint}/api/v0/cat?arg=${encodeURIComponent(cid)}`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Kubo cat failed: ${response.status} - ${errorText}`);
    }

    return new Uint8Array(await response.arrayBuffer());
  }

  /** Build auth headers for Kubo requests */
  private buildHeaders(): Record<string, string> {
    if (this.authToken) {
      return { Authorization: `Basic ${this.authToken}` };
    }
    return {};
  }
}
