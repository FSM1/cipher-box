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

/**
 * Delegated Routing V1 (https://specs.ipfs.tech/routing/http-routing-v1/): a 2xx
 * whose media type is not the record type carries no record; an unlabelled body
 * is passed up, since the engine verifies the bytes it receives.
 */
function servesRecordBytes(response: Response): boolean {
  const contentType = response.headers.get('Content-Type');
  if (contentType === null) {
    return true;
  }
  return contentType.split(';')[0].trim().toLowerCase() === IPNS_RECORD_MEDIA_TYPE;
}

/** One spelling of an endpoint URL, so two configured forms compare equal. */
function trimSlashes(endpoint: string): string {
  return endpoint.replace(/\/+$/, '');
}

export class FetchRecordTransport implements RecordTransportSeam {
  private readonly endpointList: readonly string[];
  private readonly acceleratorUrl: string | undefined;

  constructor(endpoints: string[], acceleratorUrl?: string) {
    // One spelling per endpoint: a trailing-slash twin of the accelerator would
    // read the gated leg a second time with no credential.
    const accelerator = acceleratorUrl === undefined ? undefined : trimSlashes(acceleratorUrl);
    const list = endpoints.map(trimSlashes);
    if (accelerator !== undefined && !list.includes(accelerator)) {
      list.unshift(accelerator);
    }
    if (list.length === 0) {
      throw new Error('RecordTransport endpoint set must never be empty');
    }
    this.endpointList = list;
    this.acceleratorUrl = accelerator;
  }

  endpoints(): string[] {
    return [...this.endpointList];
  }

  accelerator(): string | undefined {
    return this.acceleratorUrl;
  }

  /** The engine decides which endpoint may be shown `bearer`; this seam only sets the header. */
  async getRecord(
    endpoint: string,
    routingKey: string,
    maxBytes: number,
    bearer?: string
  ): Promise<CappedRecordResult> {
    const headers: Record<string, string> = { Accept: IPNS_RECORD_MEDIA_TYPE };
    if (bearer !== undefined) {
      headers.Authorization = `Bearer ${bearer}`;
    }
    const response = await fetch(this.recordUrl(endpoint, routingKey), {
      method: 'GET',
      headers,
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
    if (!servesRecordBytes(response)) {
      await response.body?.cancel();
      return { kind: 'record', record: null };
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
    return `${endpoint}/routing/v1/ipns/${encodeURIComponent(routingKey)}`;
  }
}
