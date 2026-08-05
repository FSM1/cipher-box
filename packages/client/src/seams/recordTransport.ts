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
 * Whole-request deadline for one record GET/PUT, so a stalled public endpoint
 * cannot park fan-out. Host policy, not a seam term — keep it in step with
 * desktop's `ReqwestRecordTransport` client timeout.
 */
const RECORD_TIMEOUT_MS = 30_000;

/**
 * Per-request policy for an endpoint set that includes untrusted public
 * endpoints: no ambient authority, and no redirects — records are directly
 * addressed, so following one only opens an SSRF-shaped vector. Mirrors
 * desktop's `ReqwestRecordTransport` client policy. A fresh signal per call.
 */
function endpointPolicy(): RequestInit {
  return {
    credentials: 'omit',
    redirect: 'error',
    signal: AbortSignal.timeout(RECORD_TIMEOUT_MS),
  };
}

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
      ...endpointPolicy(),
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
      // `record` is a live view into WASM linear memory, unlike the JS-owned
      // body `Http` receives. Copy rather than rely on `fetch` reading it
      // before any `Memory.grow()` can detach it.
      body: record.slice(),
      ...endpointPolicy(),
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
