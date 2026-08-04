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

import { drainCapped } from './cappedBody.js';
import type { CappedRecordResult, RecordTransportSeam } from './types.js';

const IPNS_RECORD_MEDIA_TYPE = 'application/vnd.ipfs.ipns-record';

/**
 * Whole-request deadline for one record GET/PUT. Records are small and directly
 * addressed, so a stalled public endpoint must fail over rather than park
 * fan-out — the bound desktop's `reqwest` transport already carries (#939).
 */
const RECORD_TIMEOUT_MS = 30_000;

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

  async getRecord(
    endpoint: string,
    routingKey: string,
    maxBytes: number
  ): Promise<CappedRecordResult> {
    const response = await fetch(this.recordUrl(endpoint, routingKey), {
      method: 'GET',
      headers: { Accept: IPNS_RECORD_MEDIA_TYPE },
      signal: AbortSignal.timeout(RECORD_TIMEOUT_MS),
    });
    if (response.status === 404) {
      await response.body?.cancel();
      return { kind: 'record', record: null };
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`RecordTransport GET ${response.status} at ${endpoint}`);
    }
    const drained = await drainCapped(response, maxBytes);
    return drained.kind === 'tooLarge' ? drained : { kind: 'record', record: drained.body };
  }

  async putRecord(endpoint: string, routingKey: string, record: Uint8Array): Promise<void> {
    const response = await fetch(this.recordUrl(endpoint, routingKey), {
      method: 'PUT',
      headers: { 'Content-Type': IPNS_RECORD_MEDIA_TYPE },
      // `fetch` copies a BufferSource body synchronously, so the engine-owned
      // view needs no defensive clone; the cast only satisfies the
      // `ArrayBufferLike` type.
      body: record as BufferSource,
      signal: AbortSignal.timeout(RECORD_TIMEOUT_MS),
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
