import type { PinningProvider, PinResult, PinStatus } from './types';

/** Fixed upload URL for Pinata file uploads (always this domain, not configurable) */
const UPLOAD_URL = 'https://uploads.pinata.cloud';

/** Timeout for all Pinata API requests (60 seconds -- uploads can be large) */
const REQUEST_TIMEOUT_MS = 60_000;

/**
 * PinningProvider implementation for Pinata's native v3 API.
 *
 * Pinata deprecated their PSA endpoint (/psa returns 404). Their current API
 * uses proprietary endpoints:
 * - /v3/files for upload and management
 * - /pinning/pinByHash for CID-based pinning
 *
 * Two base URLs are used:
 * - https://uploads.pinata.cloud -- file uploads (fixed, not configurable)
 * - https://api.pinata.cloud -- management operations (list, delete, pinByHash)
 *
 * The `endpoint` constructor param should be the management URL
 * (https://api.pinata.cloud).
 */
export class PinataProvider implements PinningProvider {
  private readonly endpoint: string;
  private readonly authToken: string;
  private readonly gatewayUrl?: string;

  constructor(endpoint: string, authToken: string, gatewayUrl?: string) {
    this.endpoint = endpoint.replace(/\/+$/, '');
    this.authToken = authToken;
    this.gatewayUrl = gatewayUrl?.replace(/\/+$/, '');
  }

  /**
   * Upload and pin data via Pinata's v3 file upload API.
   * POST https://uploads.pinata.cloud/v3/files
   */
  async pin(data: Uint8Array, name?: string): Promise<PinResult> {
    const blob = new Blob([data as BlobPart], { type: 'application/octet-stream' });
    const formData = new FormData();
    formData.append('file', blob, name ?? `cipherbox-${Date.now()}`);

    const response = await fetch(`${UPLOAD_URL}/v3/files`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.authToken}` },
      body: formData,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Pinata upload failed: ${response.status} - ${errorText}`);
    }

    const result = (await response.json()) as {
      data: { id: string; cid: string; size: number };
    };
    return { cid: result.data.cid, size: result.data.size };
  }

  /**
   * Pin an existing CID via Pinata's pinByHash endpoint.
   * Pinata will retrieve the content from the IPFS network and pin it.
   * POST https://api.pinata.cloud/pinning/pinByHash
   */
  async pinByCid(cid: string): Promise<{ cid: string; status: string }> {
    const response = await fetch(`${this.endpoint}/pinning/pinByHash`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.authToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ hashToPin: cid }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Pinata pinByHash failed: ${response.status} - ${errorText}`);
    }

    const result = (await response.json()) as { ipfsHash: string; status: string };
    return { cid: result.ipfsHash, status: result.status };
  }

  /**
   * Remove a pin by CID.
   * Pinata uses file IDs for deletion, so we first look up the file(s)
   * by CID, then delete each one.
   */
  async unpin(cid: string): Promise<void> {
    const listResponse = await fetch(`${this.endpoint}/v3/files?cid=${encodeURIComponent(cid)}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${this.authToken}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!listResponse.ok) {
      throw new Error(`Pinata list failed: ${listResponse.status}`);
    }

    const listResult = (await listResponse.json()) as {
      data: { files: Array<{ id: string }> };
    };

    for (const file of listResult.data.files) {
      const deleteResponse = await fetch(`${this.endpoint}/v3/files/${file.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${this.authToken}` },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!deleteResponse.ok) {
        throw new Error(`Pinata delete failed: ${deleteResponse.status}`);
      }
    }
  }

  /**
   * Check pin status by CID.
   * Queries the Pinata v3 files API and returns 'pinned' if found, 'failed' if not.
   */
  async status(cid: string): Promise<PinStatus> {
    const response = await fetch(`${this.endpoint}/v3/files?cid=${encodeURIComponent(cid)}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${this.authToken}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) return { cid, status: 'failed' };

    const result = (await response.json()) as {
      data: { files: Array<{ id: string; cid: string }> };
    };

    return {
      cid,
      status: result.data.files.length > 0 ? 'pinned' : 'failed',
    };
  }

  /**
   * Fetch pinned content by CID via Pinata's gateway.
   * Uses the dedicated gateway URL if configured, otherwise the default public gateway.
   */
  async get(cid: string): Promise<Uint8Array> {
    const gateway = this.gatewayUrl ?? 'https://gateway.pinata.cloud';
    const response = await fetch(`${gateway}/ipfs/${encodeURIComponent(cid)}`, {
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`Pinata gateway fetch failed: ${response.status}`);
    }

    return new Uint8Array(await response.arrayBuffer());
  }
}
