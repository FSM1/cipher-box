import { afterEach, describe, expect, it, vi } from 'vitest';

import { FetchHttp } from './http.js';
import type { HttpRequestData } from './types.js';

/** The cap itself is covered in `cappedBody.test.ts`; this is the seam wiring. */

const GET: HttpRequestData = {
  method: 'GET',
  url: 'https://gateway.example/ipfs/bafy',
  headers: [],
  body: null,
};

function stubFetch(response: Response): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(response))
  );
}

/** Stubs `fetch` and hands back the `RequestInit` each call was given. */
function recordingFetch(): { inits: RequestInit[] } {
  const inits: RequestInit[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((_url: string, init: RequestInit) => {
      inits.push(init);
      return Promise.resolve(new Response(new Uint8Array([1]), { status: 200 }));
    })
  );
  return { inits };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('FetchHttp.sendCapped', () => {
  it('surfaces an over-cap body as tooLarge rather than a response', async () => {
    stubFetch(new Response(new Uint8Array(2000), { status: 200 }));

    expect(await new FetchHttp().sendCapped(GET, 1000)).toMatchObject({ kind: 'tooLarge' });
  });

  it('returns a non-2xx status as a response, not an error', async () => {
    stubFetch(new Response(new Uint8Array([7]), { status: 418 }));

    expect(await new FetchHttp().sendCapped(GET, 1000)).toMatchObject({
      kind: 'response',
      status: 418,
      body: new Uint8Array([7]),
    });
  });

  it('carries the response headers through on the admitted path', async () => {
    stubFetch(new Response(new Uint8Array([1]), { status: 200, headers: { 'x-seam': 'value' } }));

    const result = await new FetchHttp().sendCapped(GET, 1000);

    expect(result.kind).toBe('response');
    if (result.kind !== 'response') return;
    expect(result.headers).toContainEqual(['x-seam', 'value']);
  });

  it('rejects on transport failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new Error('network down')))
    );

    await expect(new FetchHttp().sendCapped(GET, 1000)).rejects.toThrow('network down');
  });
});

describe('FetchHttp credential scoping', () => {
  it('omits ambient credentials when the request does not ask for them', async () => {
    const fetches = recordingFetch();
    const http = new FetchHttp();

    await http.send(GET);
    await http.sendCapped(GET, 1000);

    expect(fetches.inits.map((init) => init.credentials)).toEqual(['omit', 'omit']);
  });

  it('includes them only where the engine opted in', async () => {
    const fetches = recordingFetch();
    const apiRequest: HttpRequestData = { ...GET, credentials: 'include' };

    await new FetchHttp().send(apiRequest);
    await new FetchHttp().sendCapped(apiRequest, 1000);

    expect(fetches.inits.map((init) => init.credentials)).toEqual(['include', 'include']);
  });
});

describe('FetchHttp redirects', () => {
  it('refuses them on both paths, as the record transport does', async () => {
    const fetches = recordingFetch();
    const http = new FetchHttp();

    await http.send(GET);
    await http.sendCapped(GET, 1000);

    expect(fetches.inits.map((init) => init.redirect)).toEqual(['error', 'error']);
  });

  it('rejects rather than resolving when the browser refuses a hop', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch')))
    );

    await expect(new FetchHttp().send(GET)).rejects.toThrow(TypeError);
  });
});

describe('FetchHttp deadlines', () => {
  it('carries no abort signal when the request sets no deadline', async () => {
    const fetches = recordingFetch();

    await new FetchHttp().send(GET);
    await new FetchHttp().sendCapped({ ...GET, timeoutMs: null }, 1000);

    expect(fetches.inits.map((init) => init.signal)).toEqual([undefined, undefined]);
  });

  it('aborts a request that outlives its deadline', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init.signal?.addEventListener('abort', () => reject(init.signal?.reason as Error));
          })
      )
    );

    await expect(new FetchHttp().send({ ...GET, timeoutMs: 5 })).rejects.toMatchObject({
      name: 'TimeoutError',
    });
  });

  it('bounds a body that stalls mid-stream, not just the headers', async () => {
    // One chunk, then nothing: a body under the cap that never completes, so
    // only the deadline can end the drain.
    let source!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>(
      {
        start(controller) {
          source = controller;
          controller.enqueue(new Uint8Array([1, 2, 3]));
        },
      },
      { highWaterMark: 0 }
    );
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        init.signal?.addEventListener('abort', () => source.error(init.signal?.reason));
        return Promise.resolve(new Response(stream, { status: 200 }));
      })
    );

    await expect(
      new FetchHttp().sendCapped({ ...GET, timeoutMs: 5 }, 1_000_000)
    ).rejects.toMatchObject({ name: 'TimeoutError' });
  });

  // A deadline that cannot bound must refuse: these values build no signal, so
  // an unguarded seam would send them as unbounded requests.
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5])(
    'refuses a %s deadline instead of sending unbounded',
    async (timeoutMs) => {
      const fetches = recordingFetch();

      await expect(new FetchHttp().send({ ...GET, timeoutMs })).rejects.toThrow(RangeError);
      await expect(new FetchHttp().sendCapped({ ...GET, timeoutMs }, 1000)).rejects.toThrow(
        RangeError
      );
      expect(fetches.inits).toEqual([]);
    }
  );

  it('treats a zero deadline as a real deadline, not as unbounded', async () => {
    const fetches = recordingFetch();

    await new FetchHttp().send({ ...GET, timeoutMs: 0 });

    expect(fetches.inits[0]?.signal).toBeInstanceOf(AbortSignal);
  });
});
