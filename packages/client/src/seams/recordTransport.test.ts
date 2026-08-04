import { afterEach, describe, expect, it, vi } from 'vitest';

import { FetchRecordTransport } from './recordTransport.js';

const ENDPOINT = 'https://routing.example';
const KEY = 'k51qzi5uqu5dexample';

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

function transport(): FetchRecordTransport {
  return new FetchRecordTransport([ENDPOINT]);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('FetchRecordTransport.getRecord', () => {
  it('rejects an honestly-declared oversized record before reading a byte', async () => {
    const body = producedBody(100, 100);
    stubFetch(new Response(body.stream, { status: 200, headers: { 'content-length': '10000' } }));

    const result = await transport().getRecord(ENDPOINT, KEY, 1000);

    expect(result).toEqual({ kind: 'tooLarge', observed: 10000, limit: 1000 });
    expect(body.produced()).toBe(0);
    expect(body.cancelled()).toBe(true);
  });

  it('aborts at the cap when Content-Length is absent', async () => {
    const body = producedBody(100, 100);
    stubFetch(new Response(body.stream, { status: 200 }));

    const result = await transport().getRecord(ENDPOINT, KEY, 1000);

    expect(result).toEqual({ kind: 'tooLarge', observed: 1100, limit: 1000 });
    expect(body.produced()).toBeLessThanOrEqual(1100);
    expect(body.cancelled()).toBe(true);
  });

  it('aborts at the cap when Content-Length lies small', async () => {
    const body = producedBody(100, 100);
    stubFetch(new Response(body.stream, { status: 200, headers: { 'content-length': '10' } }));

    const result = await transport().getRecord(ENDPOINT, KEY, 1000);

    expect(result).toEqual({ kind: 'tooLarge', observed: 1100, limit: 1000 });
    expect(body.produced()).toBeLessThanOrEqual(1100);
    expect(body.cancelled()).toBe(true);
  });

  it('admits a record exactly at the cap with its bytes intact', async () => {
    stubFetch(new Response(new Uint8Array([1, 2, 3, 4]), { status: 200 }));

    const result = await transport().getRecord(ENDPOINT, KEY, 4);

    expect(result).toEqual({ kind: 'record', record: new Uint8Array([1, 2, 3, 4]) });
  });

  it('reports absence as a record of null, never an error', async () => {
    stubFetch(new Response(null, { status: 404 }));

    expect(await transport().getRecord(ENDPOINT, KEY, 1000)).toEqual({
      kind: 'record',
      record: null,
    });
  });

  it('throws on a non-404 failure status', async () => {
    stubFetch(new Response(null, { status: 503 }));

    await expect(transport().getRecord(ENDPOINT, KEY, 1000)).rejects.toThrow(
      'RecordTransport GET 503'
    );
  });

  it('carries an abort signal so a stalled endpoint cannot park fan-out', async () => {
    const inits: RequestInit[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        inits.push(init);
        return Promise.resolve(new Response(new Uint8Array([1]), { status: 200 }));
      })
    );

    await transport().getRecord(ENDPOINT, KEY, 1000);
    await transport().putRecord(ENDPOINT, KEY, new Uint8Array([1]));

    expect(inits.every((init) => init.signal instanceof AbortSignal)).toBe(true);
  });
});
