import type { PinningProvider, PinResult, PinStatus } from './types';

/** Timeout for all PSA requests (15 seconds — external service, conservative reduction) */
const REQUEST_TIMEOUT_MS = 15_000;

/** PSA pin object from the Pinning Service API response */
interface PsaPinObject {
  requestid: string;
  status: 'queued' | 'pinning' | 'pinned' | 'failed';
  pin: {
    cid: string;
    name?: string;
  };
}

/** PSA list response */
interface PsaListResponse {
  count: number;
  results: PsaPinObject[];
}

/**
 * PinningProvider implementation for the IPFS Pinning Service API (PSA).
 *
 * PSA is a CID-reference-only protocol: it cannot accept raw data uploads.
 * Data must be uploaded to an IPFS node first, then the CID is submitted
 * to the pinning service for retrieval and pinning.
 *
 * Supports: Pinata, web3.storage, Filebase, and any PSA-compatible service.
 */
export class PsaProvider implements PinningProvider {
  private readonly endpoint: string;
  private readonly authToken: string;

  constructor(endpoint: string, authToken: string) {
    // Normalize: strip trailing slash
    this.endpoint = endpoint.replace(/\/+$/, '');
    this.authToken = authToken;
  }

  /**
   * PSA cannot upload raw data. Always throws.
   * Use pinByCid() after uploading via CipherBox relay or a Kubo node.
   */
  async pin(_data: Uint8Array, _name?: string): Promise<PinResult> {
    throw new Error(
      'PsaProvider.pin() cannot upload raw data. Use pinByCid() after uploading via CipherBox relay or Kubo node.'
    );
  }

  /**
   * Pin a CID on the pinning service.
   * The service will retrieve the content from the IPFS network and pin it.
   */
  async pinByCid(
    cid: string,
    name?: string
  ): Promise<{ cid: string; status: PinStatus['status'] }> {
    const url = `${this.endpoint}/pins`;
    const body = {
      cid,
      name: name ?? `cipherbox-${Date.now()}`,
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: this.buildHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`PSA pin failed: ${response.status} - ${errorText}`);
    }

    const result = (await response.json()) as PsaPinObject;
    return {
      cid: result.pin.cid,
      status: result.status,
    };
  }

  /**
   * Remove a pin by CID.
   * PSA uses requestid for deletion, so we first list pins by CID
   * to find the requestid(s), then delete each one.
   */
  async unpin(cid: string): Promise<void> {
    // First, find the pin request(s) for this CID
    const listUrl = `${this.endpoint}/pins?cid=${encodeURIComponent(cid)}&status=pinned,pinning,queued`;

    const listResponse = await fetch(listUrl, {
      method: 'GET',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!listResponse.ok) {
      const errorText = await listResponse.text();
      throw new Error(`PSA list for unpin failed: ${listResponse.status} - ${errorText}`);
    }

    const listResult = (await listResponse.json()) as PsaListResponse;

    // Delete each pin request by its requestid
    for (const pin of listResult.results) {
      const deleteUrl = `${this.endpoint}/pins/${encodeURIComponent(pin.requestid)}`;

      const deleteResponse = await fetch(deleteUrl, {
        method: 'DELETE',
        headers: this.buildHeaders(),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      if (!deleteResponse.ok) {
        const errorText = await deleteResponse.text();
        throw new Error(
          `PSA delete pin ${pin.requestid} failed: ${deleteResponse.status} - ${errorText}`
        );
      }
    }
  }

  /**
   * Check pin status by CID.
   * Queries the pinning service for the latest status of a CID.
   */
  async status(cid: string): Promise<PinStatus> {
    const url = `${this.endpoint}/pins?cid=${encodeURIComponent(cid)}&limit=1`;

    const response = await fetch(url, {
      method: 'GET',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      return { cid, status: 'failed' };
    }

    const result = (await response.json()) as PsaListResponse;

    if (result.count === 0 || result.results.length === 0) {
      return { cid, status: 'failed' };
    }

    return {
      cid,
      status: result.results[0].status,
    };
  }

  /**
   * PSA does not support content retrieval. Always throws.
   * Use an IPFS gateway to fetch content by CID.
   */
  async get(_cid: string): Promise<Uint8Array> {
    throw new Error('PsaProvider does not support content retrieval. Use an IPFS gateway.');
  }

  /** Build auth headers with Bearer token */
  private buildHeaders(extra?: Record<string, string>): Record<string, string> {
    return {
      Authorization: `Bearer ${this.authToken}`,
      ...extra,
    };
  }
}
