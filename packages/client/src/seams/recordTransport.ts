/**
 * `RecordTransport` — a dumb `/routing/v1` byte mover over `fetch`
 * (blueprint/web-client.md seam table).
 *
 * GET/PUT of opaque signed record bytes against the configured endpoint set
 * (CipherBox someguy plus at least one independent public endpoint). The engine
 * owns IPNS end-to-end — signing, verification, CAS, fan-out, and every trust
 * decision — so this seam never inspects, caches, or reorders records; it only
 * addresses `routingKey` and moves bytes. Absence is `null`, never an error;
 * a rejected promise is reserved for transport-level failure.
 */

import type { RecordTransportSeam } from './types.js';

const IPNS_RECORD_MEDIA_TYPE = 'application/vnd.ipfs.ipns-record';

export class FetchRecordTransport implements RecordTransportSeam {
  private readonly endpointList: readonly string[];

  constructor(endpoints: string[]) {
    if (endpoints.length === 0) {
      throw new Error('RecordTransport endpoint set must never be empty');
    }
    this.endpointList = [...endpoints];
  }

  endpoints(): string[] {
    return [...this.endpointList];
  }

  async getRecord(endpoint: string, routingKey: string): Promise<Uint8Array | null> {
    const response = await fetch(this.recordUrl(endpoint, routingKey), {
      method: 'GET',
      headers: { Accept: IPNS_RECORD_MEDIA_TYPE },
    });
    if (response.status === 404) return null;
    if (!response.ok) {
      throw new Error(`RecordTransport GET ${response.status} at ${endpoint}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  async putRecord(endpoint: string, routingKey: string, record: Uint8Array): Promise<void> {
    const response = await fetch(this.recordUrl(endpoint, routingKey), {
      method: 'PUT',
      headers: { 'Content-Type': IPNS_RECORD_MEDIA_TYPE },
      // Copy into an ArrayBuffer-backed view so `fetch` accepts the body
      // (a possibly-shared `ArrayBufferLike` is rejected).
      body: new Uint8Array(record),
    });
    if (!response.ok) {
      throw new Error(`RecordTransport PUT ${response.status} at ${endpoint}`);
    }
  }

  private recordUrl(endpoint: string, routingKey: string): string {
    const base = endpoint.replace(/\/+$/, '');
    return `${base}/routing/v1/ipns/${encodeURIComponent(routingKey)}`;
  }
}
