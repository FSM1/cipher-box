import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { RoutingV1RecordTransport } from './record-transport';

const MAX_RECORD_BYTES = 64 * 1024;

/**
 * Fake `/routing/v1` response backed by a chunked ReadableStream reader, letting
 * each test set the body, chunk size, and Content-Length header independently.
 * The reader is a spy so a test can assert an honestly-declared oversized body is
 * rejected BEFORE any byte is read, and that an over-cap stream is cancelled
 * mid-flight rather than buffered whole (the header cannot be trusted).
 */
function fakeResponse(opts: {
  status?: number;
  body?: Buffer;
  contentLength?: string | null;
  chunkSize?: number;
}): {
  response: Response;
  read: ReturnType<typeof vi.fn>;
  readerCancel: ReturnType<typeof vi.fn>;
  bodyCancel: ReturnType<typeof vi.fn>;
} {
  const body = opts.body ?? Buffer.alloc(0);
  const status = opts.status ?? 200;
  const chunkSize = opts.chunkSize ?? 16 * 1024;
  const contentLength =
    opts.contentLength === undefined ? String(body.byteLength) : opts.contentLength;

  let offset = 0;
  const read = vi.fn(async () => {
    if (offset >= body.byteLength) {
      return { done: true, value: undefined };
    }
    const end = Math.min(offset + chunkSize, body.byteLength);
    const value = new Uint8Array(body.subarray(offset, end));
    offset = end;
    return { done: false, value };
  });
  const readerCancel = vi.fn(async () => {});
  const bodyCancel = vi.fn(async () => {});

  const response = {
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get: (name: string) => (name.toLowerCase() === 'content-length' ? contentLength : null),
    },
    body: {
      getReader: () => ({ read, cancel: readerCancel }),
      cancel: bodyCancel,
    },
  } as unknown as Response;
  return { response, read, readerCancel, bodyCancel };
}

function transport(routingUrl = 'https://routing.test'): RoutingV1RecordTransport {
  return new RoutingV1RecordTransport(fakeConfig({ ROUTING_V1_URL: routingUrl }).service);
}

describe('RoutingV1RecordTransport response-size cap', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns an in-bounds body at exactly the ceiling', async () => {
    const body = Buffer.alloc(MAX_RECORD_BYTES, 7);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => fakeResponse({ body }).response)
    );

    const result = await transport().resolve('k51-in-bounds');
    expect(result?.byteLength).toBe(MAX_RECORD_BYTES);
    expect(result?.equals(body)).toBe(true);
  });

  it('returns a small chunked body reassembled from multiple reads', async () => {
    const body = Buffer.from('signed-ipns-record-bytes');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => fakeResponse({ body, contentLength: null, chunkSize: 4 }).response)
    );

    const result = await transport().resolve('k51-chunked');
    expect(result?.equals(body)).toBe(true);
  });

  it('rejects an honestly-declared oversized body before reading it', async () => {
    const { response, read, bodyCancel } = fakeResponse({
      body: Buffer.alloc(8),
      contentLength: String(MAX_RECORD_BYTES + 1),
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => response)
    );

    await expect(transport().resolve('k51-declared')).rejects.toThrow(/exceeds/);
    expect(read).not.toHaveBeenCalled();
    expect(bodyCancel).toHaveBeenCalledTimes(1);
  });

  it('rejects and cancels an oversized stream whose Content-Length is absent', async () => {
    const body = Buffer.alloc(MAX_RECORD_BYTES + 1, 3);
    const { response, readerCancel } = fakeResponse({
      body,
      contentLength: null,
      chunkSize: 16 * 1024,
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => response)
    );

    await expect(transport().resolve('k51-absent')).rejects.toThrow(/exceeds/);
    expect(readerCancel).toHaveBeenCalledTimes(1);
  });

  it('rejects and cancels an oversized stream whose Content-Length lies small', async () => {
    const body = Buffer.alloc(MAX_RECORD_BYTES + 1, 5);
    const { response, readerCancel } = fakeResponse({
      body,
      contentLength: '10',
      chunkSize: 16 * 1024,
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => response)
    );

    await expect(transport().resolve('k51-lying')).rejects.toThrow(/exceeds/);
    expect(readerCancel).toHaveBeenCalledTimes(1);
  });

  it('bounds heap by cancelling mid-stream instead of draining the whole body', async () => {
    // A GB-scale stream in tiny chunks: the cap must trip ~one chunk past the
    // ceiling and cancel, never draining every chunk (post-facto buffering would).
    const oneGiB = 1024 * 1024 * 1024;
    const chunkSize = 16 * 1024;
    let served = 0;
    const read = vi.fn(async () => {
      if (served >= oneGiB) {
        return { done: true, value: undefined };
      }
      served += chunkSize;
      return { done: false, value: new Uint8Array(chunkSize) };
    });
    const readerCancel = vi.fn(async () => {});
    const response = {
      status: 200,
      ok: true,
      headers: { get: () => null },
      body: { getReader: () => ({ read, cancel: readerCancel }), cancel: vi.fn() },
    } as unknown as Response;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => response)
    );

    await expect(transport().resolve('k51-flood')).rejects.toThrow(/exceeds/);
    expect(readerCancel).toHaveBeenCalledTimes(1);
    // Cap is 64 KiB; one chunk past = 5 reads. Assert we stopped far below the GB.
    expect(read.mock.calls.length).toBeLessThan(16);
  });
});

describe('RoutingV1RecordTransport configuration report', () => {
  let errorSpy: MockInstance<Logger['error']>;

  beforeEach(() => {
    errorSpy = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('names the unset variable and its consequence at construction', () => {
    transport('');
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('ROUTING_V1_URL'));
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('walk'));
  });

  it('stays silent when the routing endpoint is configured', () => {
    transport();
    expect(errorSpy).not.toHaveBeenCalled();
  });
});
