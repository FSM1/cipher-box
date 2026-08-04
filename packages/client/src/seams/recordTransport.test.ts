import { afterEach, describe, expect, it, vi } from 'vitest';

import { FetchRecordTransport } from './recordTransport.js';

/** The cap itself is covered in `cappedBody.test.ts`; this is the seam wiring. */

const ENDPOINT = 'https://routing.example';
const KEY = 'k51qzi5uqu5dexample';

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
  it('surfaces an over-cap record as tooLarge, never as bytes', async () => {
    stubFetch(new Response(new Uint8Array(2000), { status: 200 }));

    expect(await transport().getRecord(ENDPOINT, KEY, 1000)).toEqual({
      kind: 'tooLarge',
      observed: 2000,
      limit: 1000,
    });
  });

  it('admits a record exactly at the cap with its bytes intact', async () => {
    stubFetch(new Response(new Uint8Array([1, 2, 3, 4]), { status: 200 }));

    expect(await transport().getRecord(ENDPOINT, KEY, 4)).toEqual({
      kind: 'record',
      record: new Uint8Array([1, 2, 3, 4]),
    });
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

  it('gives an untrusted endpoint no ambient authority, no redirects, and a deadline', async () => {
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

    expect(inits.map((init) => init.credentials)).toEqual(['omit', 'omit']);
    expect(inits.map((init) => init.redirect)).toEqual(['error', 'error']);
    expect(inits.every((init) => init.signal instanceof AbortSignal)).toBe(true);
    // A shared signal would abort every later request once the first deadline
    // elapsed; each call must build its own.
    expect(inits[0].signal).not.toBe(inits[1].signal);
  });
});
