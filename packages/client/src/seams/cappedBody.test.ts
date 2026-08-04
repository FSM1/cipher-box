import { describe, expect, it } from 'vitest';

import { drainCapped } from './cappedBody.js';

/**
 * The streaming cap both untrusted-origin seams share; `http.test.ts` and
 * `recordTransport.test.ts` cover only how each seam wires into it.
 */

interface ProducedBody {
  stream: ReadableStream<Uint8Array>;
  /** Bytes the source actually generated — the real peak-memory witness. */
  produced: () => number;
  cancelled: () => boolean;
}

/** A lazily generated body of `chunkCount` chunks that tracks what was pulled. */
function producedBody(chunkSize: number, chunkCount: number): ProducedBody {
  let produced = 0;
  let cancelled = false;
  let emitted = 0;
  // `highWaterMark: 0` keeps the source strictly demand-driven, so `produced`
  // counts exactly what the drain pulled and nothing the stream buffered ahead.
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (emitted === chunkCount) {
          controller.close();
          return;
        }
        emitted += 1;
        produced += chunkSize;
        controller.enqueue(new Uint8Array(chunkSize).fill(emitted));
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 }
  );
  return { stream, produced: () => produced, cancelled: () => cancelled };
}

function respond(body: ProducedBody, contentLength?: string): Response {
  return new Response(body.stream, {
    status: 200,
    headers: contentLength === undefined ? {} : { 'content-length': contentLength },
  });
}

describe('drainCapped', () => {
  it('rejects an honestly-declared oversized body before reading a byte', async () => {
    const body = producedBody(100, 100);

    expect(await drainCapped(respond(body, '10000'), 1000)).toEqual({
      kind: 'tooLarge',
      observed: 10000,
      limit: 1000,
    });
    expect(body.produced()).toBe(0);
    expect(body.cancelled()).toBe(true);
  });

  // An absent Content-Length, one that lies small, `abc` (NaN), and `-1` all
  // slip past the declared-size check; the streaming cap is the only gate left.
  it.each([undefined, '10', 'abc', '-1'])(
    'aborts at the cap on Content-Length %s',
    async (declared) => {
      const body = producedBody(100, 100);

      expect(await drainCapped(respond(body, declared), 1000)).toEqual({
        kind: 'tooLarge',
        observed: 1100,
        limit: 1000,
      });
      // Never the whole 10 KB body: the cap plus at most the chunk that tripped it.
      expect(body.produced()).toBeLessThanOrEqual(1100);
      expect(body.cancelled()).toBe(true);
    }
  );

  it('rejects a single chunk larger than the whole cap', async () => {
    const body = producedBody(4096, 4);

    // Nothing is accumulated before the first chunk, so the whole overshoot is
    // that one chunk — the peak the bound admits.
    expect(await drainCapped(respond(body), 1000)).toEqual({
      kind: 'tooLarge',
      observed: 4096,
      limit: 1000,
    });
    expect(body.produced()).toBe(4096);
    expect(body.cancelled()).toBe(true);
  });

  it('admits a body exactly at the cap with its bytes intact', async () => {
    const body = producedBody(100, 10);

    const result = await drainCapped(respond(body), 1000);

    expect(result.kind).toBe('body');
    if (result.kind !== 'body') return;
    expect(result.body.length).toBe(1000);
    expect(result.body[0]).toBe(1);
    expect(result.body[999]).toBe(10);
    expect(body.cancelled()).toBe(false);
  });

  it('reassembles a small body arriving over multiple reads', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.enqueue(new Uint8Array([3]));
        controller.enqueue(new Uint8Array([4, 5, 6]));
        controller.close();
      },
    });

    expect(await drainCapped(new Response(stream, { status: 200 }), 1000)).toEqual({
      kind: 'body',
      body: new Uint8Array([1, 2, 3, 4, 5, 6]),
    });
  });

  it('drops empty chunks instead of retaining them against the cap', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 5; i += 1) controller.enqueue(new Uint8Array(0));
        controller.enqueue(new Uint8Array([1, 2, 3]));
        controller.close();
      },
    });

    expect(await drainCapped(new Response(stream, { status: 200 }), 1000)).toEqual({
      kind: 'body',
      body: new Uint8Array([1, 2, 3]),
    });
  });

  it('treats a null body as an empty body', async () => {
    expect(await drainCapped(new Response(null, { status: 204 }), 1000)).toEqual({
      kind: 'body',
      body: new Uint8Array(),
    });
  });

  // A cap that cannot bound must refuse. `NaN` and `Infinity` are the dangerous
  // pair: both size comparisons go false, so an unguarded drain runs unbounded.
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5])(
    'refuses a %s cap without reading the body',
    async (maxBytes) => {
      const body = producedBody(100, 100);

      await expect(drainCapped(respond(body), maxBytes)).rejects.toThrow(RangeError);
      expect(body.produced()).toBe(0);
      expect(body.cancelled()).toBe(true);
    }
  );

  it('admits a zero cap only for an empty body', async () => {
    expect(await drainCapped(new Response(null, { status: 204 }), 0)).toEqual({
      kind: 'body',
      body: new Uint8Array(),
    });

    const body = producedBody(1, 1);
    expect(await drainCapped(respond(body), 0)).toEqual({
      kind: 'tooLarge',
      observed: 1,
      limit: 0,
    });
  });
});
