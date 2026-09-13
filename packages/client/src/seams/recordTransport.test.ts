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

  it('reads a 200 text answer as absence, the way a real endpoint reports a missing name', async () => {
    stubFetch(
      new Response('delegate error: routing: not found', {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      })
    );

    expect(await transport().getRecord(ENDPOINT, KEY, 1000)).toEqual({
      kind: 'record',
      record: null,
    });
  });

  it('returns the bytes of a 200 that declares the record media type', async () => {
    stubFetch(
      new Response(new Uint8Array([7, 8, 9]), {
        status: 200,
        headers: { 'Content-Type': 'application/vnd.ipfs.ipns-record' },
      })
    );

    expect(await transport().getRecord(ENDPOINT, KEY, 1000)).toEqual({
      kind: 'record',
      record: new Uint8Array([7, 8, 9]),
    });
  });

  it('returns the bytes when the record media type arrives in mixed case', async () => {
    stubFetch(
      new Response(new Uint8Array([1, 2]), {
        status: 200,
        headers: { 'Content-Type': 'Application/VND.IPFS.IPNS-RECORD; charset=x' },
      })
    );

    expect(await transport().getRecord(ENDPOINT, KEY, 1000)).toEqual({
      kind: 'record',
      record: new Uint8Array([1, 2]),
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

/** The header the gated CipherBox resolve leg reads, of the request `init`. */
function authorizationOf(init: RequestInit): string | undefined {
  return (init.headers as Record<string, string>).Authorization;
}

describe('FetchRecordTransport bearer presentation', () => {
  function recordingFetch(): RequestInit[] {
    const inits: RequestInit[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        inits.push(init);
        return Promise.resolve(new Response(new Uint8Array([1]), { status: 200 }));
      })
    );
    return inits;
  }

  it('sends the bearer a GET is given as an Authorization header', async () => {
    const inits = recordingFetch();

    await transport().getRecord(ENDPOINT, KEY, 1000, 'a-pseudonym');

    expect(authorizationOf(inits[0])).toBe('Bearer a-pseudonym');
  });

  it('sends no Authorization header on a GET given no bearer', async () => {
    const inits = recordingFetch();

    await transport().getRecord(ENDPOINT, KEY, 1000);

    expect(authorizationOf(inits[0])).toBeUndefined();
  });

  it('never sends an Authorization header on a PUT', async () => {
    const inits = recordingFetch();

    await transport().putRecord(ENDPOINT, KEY, new Uint8Array([1]));

    expect(authorizationOf(inits[0])).toBeUndefined();
  });
});

describe('FetchRecordTransport.accelerator', () => {
  const ACCELERATOR = 'https://accelerator.example';

  it('reports the configured accelerator and carries it in the endpoint set', () => {
    const configured = new FetchRecordTransport([ENDPOINT], ACCELERATOR);

    expect(configured.accelerator()).toBe(ACCELERATOR);
    expect(configured.endpoints()).toEqual([ACCELERATOR, ENDPOINT]);
  });

  it('keeps one entry for an accelerator the endpoint list already names', () => {
    const configured = new FetchRecordTransport([ENDPOINT, ACCELERATOR], ACCELERATOR);

    expect(configured.endpoints()).toEqual([ENDPOINT, ACCELERATOR]);
  });

  it('reports no accelerator when the host configured none', () => {
    expect(transport().accelerator()).toBeUndefined();
  });

  it('accepts an accelerator as the whole endpoint set', () => {
    expect(new FetchRecordTransport([], ACCELERATOR).endpoints()).toEqual([ACCELERATOR]);
  });

  it('still refuses an empty endpoint set', () => {
    expect(() => new FetchRecordTransport([])).toThrow('must never be empty');
  });
});
