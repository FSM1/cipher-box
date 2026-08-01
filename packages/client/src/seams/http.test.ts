import { afterEach, describe, expect, it, vi } from 'vitest';

import { FetchHttp } from './http.js';
import type { HttpRequestData } from './types.js';

const GET: HttpRequestData = {
  method: 'GET',
  url: 'https://gateway.example/ipfs/bafy',
  headers: [],
  body: null,
};

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
  // counts exactly what the seam pulled and nothing the stream buffered ahead.
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

function stubFetch(response: Response): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(response))
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('FetchHttp.sendCapped', () => {
  it('rejects an honestly-declared oversized body before reading a byte', async () => {
    const body = producedBody(100, 100);
    stubFetch(new Response(body.stream, { status: 200, headers: { 'content-length': '10000' } }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result).toEqual({ kind: 'tooLarge', observed: 10000, limit: 1000 });
    expect(body.produced()).toBe(0);
    expect(body.cancelled()).toBe(true);
  });

  it('aborts at the cap when Content-Length is absent', async () => {
    const body = producedBody(100, 100);
    stubFetch(new Response(body.stream, { status: 200 }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result).toEqual({ kind: 'tooLarge', observed: 1100, limit: 1000 });
    // Never the whole 10 KB body: the cap plus at most the chunk that tripped it.
    expect(body.produced()).toBeLessThanOrEqual(1100);
    expect(body.cancelled()).toBe(true);
  });

  it('aborts at the cap when Content-Length lies small', async () => {
    const body = producedBody(100, 100);
    stubFetch(new Response(body.stream, { status: 200, headers: { 'content-length': '10' } }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result).toEqual({ kind: 'tooLarge', observed: 1100, limit: 1000 });
    expect(body.produced()).toBeLessThanOrEqual(1100);
    expect(body.cancelled()).toBe(true);
  });

  it('admits a body exactly at the cap with its bytes intact', async () => {
    const body = producedBody(100, 10);
    stubFetch(new Response(body.stream, { status: 200 }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result.kind).toBe('response');
    if (result.kind !== 'response') return;
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
    stubFetch(new Response(stream, { status: 200 }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result).toMatchObject({ kind: 'response', body: new Uint8Array([1, 2, 3, 4, 5, 6]) });
  });

  it('drops empty chunks instead of retaining them against the cap', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 5; i += 1) controller.enqueue(new Uint8Array(0));
        controller.enqueue(new Uint8Array([1, 2, 3]));
        controller.close();
      },
    });
    stubFetch(new Response(stream, { status: 200 }));
    // Every retained chunk costs one copy at assembly, so the copy count is what
    // a body of empty reads would grow without bound.
    const copies = vi.spyOn(Uint8Array.prototype, 'set');

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result).toMatchObject({ kind: 'response', body: new Uint8Array([1, 2, 3]) });
    expect(copies).toHaveBeenCalledTimes(1);
    copies.mockRestore();
  });

  it('treats a null body as an empty body', async () => {
    stubFetch(new Response(null, { status: 204 }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result).toMatchObject({ kind: 'response', status: 204, body: new Uint8Array() });
  });

  it('returns a non-2xx status as a response, not an error', async () => {
    stubFetch(new Response(new Uint8Array([7]), { status: 418 }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result).toMatchObject({ kind: 'response', status: 418, body: new Uint8Array([7]) });
  });

  it('rejects on transport failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new Error('network down')))
    );

    await expect(new FetchHttp().sendCapped(GET, 1000)).rejects.toThrow('network down');
  });
});
