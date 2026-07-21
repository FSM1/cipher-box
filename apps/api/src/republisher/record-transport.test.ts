import { afterEach, describe, expect, it, vi } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { RoutingV1RecordTransport } from './record-transport';

const MAX_RECORD_BYTES = 64 * 1024;

/**
 * Fake `/routing/v1` response letting each test set the body and the
 * Content-Length header independently, so the absent/lying-header paths are
 * exercised (the header cannot be trusted). `arrayBuffer` is a spy so a test can
 * assert an honestly-declared oversized body is rejected BEFORE it is buffered.
 */
function fakeResponse(opts: { status?: number; body?: Buffer; contentLength?: string | null }): {
  response: Response;
  arrayBuffer: ReturnType<typeof vi.fn>;
} {
  const body = opts.body ?? Buffer.alloc(0);
  const status = opts.status ?? 200;
  const contentLength =
    opts.contentLength === undefined ? String(body.byteLength) : opts.contentLength;
  const arrayBuffer = vi.fn(async () =>
    body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)
  );
  const response = {
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get: (name: string) => (name.toLowerCase() === 'content-length' ? contentLength : null),
    },
    arrayBuffer,
  } as unknown as Response;
  return { response, arrayBuffer };
}

function transport(): RoutingV1RecordTransport {
  return new RoutingV1RecordTransport(
    fakeConfig({ ROUTING_V1_URL: 'https://routing.test' }).service
  );
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

  it('rejects an honestly-declared oversized body before buffering it', async () => {
    const { response, arrayBuffer } = fakeResponse({
      body: Buffer.alloc(8),
      contentLength: String(MAX_RECORD_BYTES + 1),
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => response)
    );

    await expect(transport().resolve('k51-declared')).rejects.toThrow(/exceeds/);
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  it('rejects an oversized body whose Content-Length is absent', async () => {
    const body = Buffer.alloc(MAX_RECORD_BYTES + 1, 3);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => fakeResponse({ body, contentLength: null }).response)
    );

    await expect(transport().resolve('k51-absent')).rejects.toThrow(/exceeds/);
  });

  it('rejects an oversized body whose Content-Length lies small', async () => {
    const body = Buffer.alloc(MAX_RECORD_BYTES + 1, 5);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => fakeResponse({ body, contentLength: '10' }).response)
    );

    await expect(transport().resolve('k51-lying')).rejects.toThrow(/exceeds/);
  });
});
