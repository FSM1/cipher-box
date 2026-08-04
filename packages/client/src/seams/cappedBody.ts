/**
 * The streaming size cap shared by the `fetch`-backed seams that read from
 * untrusted origins — content blocks over {@link HttpSeam} and `/routing/v1`
 * records over {@link RecordTransportSeam}.
 *
 * The cap is enforced as bytes arrive, so a gateway that omits or lies about
 * `Content-Length` cannot force an unbounded buffer. `fetch` hands over whole
 * chunks, so the drain aborts on the chunk that would pass the cap: the
 * retained body never exceeds `maxBytes`, and peak memory is `maxBytes` —
 * about twice it while the chunks are concatenated — plus that one chunk.
 * `maxBytes` is inclusive: a body of exactly `maxBytes` is admitted.
 */

import type { TooLargeResult } from './types.js';

/** A drained body, or a fail-closed rejection of one over the cap. */
export type CappedBody = { kind: 'body'; body: Uint8Array } | TooLargeResult;

export async function drainCapped(response: Response, maxBytes: number): Promise<CappedBody> {
  // Both size comparisons below are false for a NaN or infinite cap, so an
  // unusable bound would drain without one. A cap that cannot bound is a
  // refusal, never an unbounded read.
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    await response.body?.cancel();
    throw new RangeError(
      `drainCapped: maxBytes must be a non-negative safe integer, got ${maxBytes}`
    );
  }

  const contentLength = response.headers.get('content-length');
  const declared = contentLength === null ? Number.NaN : Number(contentLength);
  if (Number.isFinite(declared) && declared > maxBytes) {
    // Release the connection instead of leaking an unread body stream.
    await response.body?.cancel();
    return { kind: 'tooLarge', observed: declared, limit: maxBytes };
  }

  const reader = response.body?.getReader();
  if (!reader) {
    return { kind: 'body', body: new Uint8Array() };
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
  return { kind: 'body', body };
}
