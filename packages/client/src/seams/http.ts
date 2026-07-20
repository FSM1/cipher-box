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

import type { HttpRequestData, HttpResponseData, HttpSeam } from './types.js';

export class FetchHttp implements HttpSeam {
  async send(request: HttpRequestData): Promise<HttpResponseData> {
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

    const response = await fetch(request.url, init);

    const responseHeaders: Array<[string, string]> = [];
    response.headers.forEach((value, name) => {
      responseHeaders.push([name, value]);
    });

    return {
      status: response.status,
      headers: responseHeaders,
      body: new Uint8Array(await response.arrayBuffer()),
    };
  }
}
