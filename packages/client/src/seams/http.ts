/**
 * `Http` — plain HTTP over `fetch` (blueprint/web-client.md seam table).
 *
 * Backs the engine's hand-written API client, the trustless gateway read path,
 * and BYO pin providers. A pure byte mover: it adds no headers the engine did
 * not ask for and never interprets bodies. Ambient credentials ride only where
 * the request asks for them — `credentials: 'include'` on the API origin
 * carries the HTTP-only refresh cookie, which is exactly why web's
 * {@link CredentialStoreSeam} is a no-op. Non-2xx statuses are responses, not
 * errors; only a transport-level failure (unreachable, aborted, deadline
 * elapsed) rejects.
 */

import { drainCapped } from './cappedBody.js';
import type { CappedHttpResult, HttpRequestData, HttpResponseData, HttpSeam } from './types.js';

function requestInit(request: HttpRequestData): RequestInit {
  const headers = new Headers();
  for (const [name, value] of request.headers) {
    headers.append(name, value);
  }

  const init: RequestInit = {
    method: request.method,
    headers,
    // Fail-safe default: authority is opt-in per request, never inferred.
    credentials: request.credentials ?? 'omit',
    // Every target here is directly addressed and gated on the URL the engine
    // supplied, so a hop the engine did not choose can only escape that gate.
    // Mirrors `FetchRecordTransport`; a redirect rejects rather than resolving.
    redirect: 'error',
  };
  const timeoutMs = request.timeoutMs;
  if (timeoutMs !== undefined && timeoutMs !== null) {
    // A negative or non-finite deadline builds no signal, silently widening a
    // bounded request to unbounded. Zero stays a real deadline that aborts
    // here, as it does on desktop's `reqwest`.
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
      throw new RangeError(`timeoutMs must be a non-negative safe integer, got ${timeoutMs}`);
    }
    // Bounds the whole exchange, body stream included — the reader below
    // rejects when the signal fires mid-drain.
    init.signal = AbortSignal.timeout(timeoutMs);
  }
  if (request.body !== null && request.method !== 'GET' && request.method !== 'HEAD') {
    // `fetch` copies a BufferSource body synchronously, so the engine-owned
    // bytes need no defensive clone; the cast only satisfies the
    // `ArrayBufferLike` type.
    init.body = request.body as BufferSource;
  }
  return init;
}

function collectHeaders(response: Response): Array<[string, string]> {
  const headers: Array<[string, string]> = [];
  response.headers.forEach((value, name) => {
    headers.push([name, value]);
  });
  return headers;
}

export class FetchHttp implements HttpSeam {
  async send(request: HttpRequestData): Promise<HttpResponseData> {
    const response = await fetch(request.url, requestInit(request));
    return {
      status: response.status,
      headers: collectHeaders(response),
      body: new Uint8Array(await response.arrayBuffer()),
    };
  }

  async sendCapped(request: HttpRequestData, maxBytes: number): Promise<CappedHttpResult> {
    const response = await fetch(request.url, requestInit(request));
    const status = response.status;
    const drained = await drainCapped(response, maxBytes);
    return drained.kind === 'tooLarge'
      ? drained
      : { kind: 'response', status, headers: collectHeaders(response), body: drained.body };
  }
}
