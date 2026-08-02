/**
 * `Http` — plain HTTP over `fetch`, with `credentials: 'include'`
 * (blueprint/web-client.md seam table).
 *
 * Backs the engine's hand-written API client, the trustless gateway read path,
 * and BYO pin providers. A pure byte mover: it adds no headers the engine did
 * not ask for and never interprets bodies. `credentials: 'include'` carries the
 * HTTP-only refresh cookie on the API origin — which is exactly why web's
 * {@link CredentialStoreSeam} is a no-op. Non-2xx statuses are responses, not
 * errors; only a transport-level failure (unreachable, aborted) rejects.
 */

import type { CappedHttpResult, HttpRequestData, HttpResponseData, HttpSeam } from './types.js';

function requestInit(request: HttpRequestData): RequestInit {
  const headers = new Headers();
  for (const [name, value] of request.headers) {
    headers.append(name, value);
  }

  const init: RequestInit = {
    method: request.method,
    headers,
    credentials: 'include',
  };
  if (request.body !== null && request.method !== 'GET' && request.method !== 'HEAD') {
    // Copy into an ArrayBuffer-backed view: `fetch` rejects a
    // possibly-shared `ArrayBufferLike`-backed body. v2.0 uses no
    // SharedArrayBuffer, so this only satisfies the type.
    init.body = new Uint8Array(request.body);
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

  /**
   * Enforces the cap as bytes arrive, even when Content-Length is absent or
   * lies. `fetch` hands over whole chunks, so the drain aborts on the chunk
   * that would pass the cap: the retained body never exceeds `maxBytes`, and
   * peak memory is `maxBytes` — about twice it while the chunks are
   * concatenated — plus that one chunk.
   */
  async sendCapped(request: HttpRequestData, maxBytes: number): Promise<CappedHttpResult> {
    const response = await fetch(request.url, requestInit(request));

    const contentLength = response.headers.get('content-length');
    const declared = contentLength === null ? Number.NaN : Number(contentLength);
    if (Number.isFinite(declared) && declared > maxBytes) {
      // Release the connection instead of leaking an unread body stream.
      await response.body?.cancel();
      return { kind: 'tooLarge', observed: declared, limit: maxBytes };
    }

    const status = response.status;
    const headers = collectHeaders(response);
    const reader = response.body?.getReader();
    if (!reader) {
      return { kind: 'response', status, headers, body: new Uint8Array() };
    }

    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      // An empty chunk carries no bytes to count, so retaining it would grow the
      // chunk list without ever tripping the cap.
      if (!value || value.byteLength === 0) {
        continue;
      }
      if (total + value.byteLength > maxBytes) {
        await reader.cancel();
        return { kind: 'tooLarge', observed: total + value.byteLength, limit: maxBytes };
      }
      chunks.push(value);
      total += value.byteLength;
    }

    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { kind: 'response', status, headers, body };
  }
}
