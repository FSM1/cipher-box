import { HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DelegatedRoutingClient } from './delegated-routing.client';

// Mock global fetch
const mockFetch = jest.fn();
global.fetch = mockFetch;

function createMockResponse(
  status: number,
  opts: { body?: string; buffer?: ArrayBuffer; headers?: Record<string, string> } = {}
): Response {
  const { body = '', buffer, headers = {} } = opts;
  const headerMap = new Map(Object.entries(headers));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (key: string) => headerMap.get(key) ?? null },
    text: jest.fn().mockResolvedValue(body),
    arrayBuffer: jest.fn().mockResolvedValue(buffer ?? new ArrayBuffer(0)),
  } as unknown as Response;
}

describe('DelegatedRoutingClient', () => {
  let client: DelegatedRoutingClient;
  let configService: ConfigService;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let delaySpy: jest.SpyInstance<Promise<void>, [ms: number], any>;

  beforeEach(() => {
    jest.restoreAllMocks();
    mockFetch.mockReset();

    configService = {
      get: jest.fn().mockReturnValue('https://routing.example.com'),
    } as unknown as ConfigService;

    client = new DelegatedRoutingClient(configService);

    // Eliminate real delays by making delay() resolve instantly
    delaySpy = jest.spyOn(client as never, 'delay' as never).mockResolvedValue(undefined as never);
  });

  describe('constructor', () => {
    it('reads DELEGATED_ROUTING_URL from config', () => {
      expect(configService.get).toHaveBeenCalledWith(
        'DELEGATED_ROUTING_URL',
        'https://delegated-ipfs.dev'
      );
    });
  });

  describe('publish', () => {
    const ipnsName = 'k51qzi5uqu5dg12345';
    const recordBytes = new Uint8Array([1, 2, 3]);

    it('publishes successfully on first attempt', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(200));

      await client.publish(ipnsName, recordBytes);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe(
        `https://routing.example.com/routing/v1/ipns/${encodeURIComponent(ipnsName)}`
      );
      expect(init.method).toBe('PUT');
      expect(init.headers['Content-Type']).toBe('application/vnd.ipfs.ipns-record');
    });

    it('throws BAD_GATEWAY on non-retryable HTTP error', async () => {
      mockFetch.mockResolvedValue(createMockResponse(500, { body: 'Internal Server Error' }));

      const error = await client.publish(ipnsName, recordBytes).catch((e) => e);

      expect(error).toBeInstanceOf(HttpException);
      expect(error.getStatus()).toBe(HttpStatus.BAD_GATEWAY);
      // Should not retry — only one fetch call
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('retries on network errors with exponential backoff', async () => {
      mockFetch
        .mockRejectedValueOnce(new Error('fetch failed'))
        .mockRejectedValueOnce(new Error('fetch failed'))
        .mockResolvedValueOnce(createMockResponse(200));

      await client.publish(ipnsName, recordBytes);

      expect(mockFetch).toHaveBeenCalledTimes(3);
      // Delay called twice (attempts 0 and 1)
      expect(delaySpy).toHaveBeenCalledTimes(2);
      expect(delaySpy).toHaveBeenNthCalledWith(1, 1000); // 1000 * 2^0
      expect(delaySpy).toHaveBeenNthCalledWith(2, 2000); // 1000 * 2^1
    });

    it('throws BAD_GATEWAY after exhausting retries on network errors', async () => {
      mockFetch.mockRejectedValue(new Error('fetch failed'));

      const error = await client.publish(ipnsName, recordBytes).catch((e) => e);

      expect(error).toBeInstanceOf(HttpException);
      expect(error.getStatus()).toBe(HttpStatus.BAD_GATEWAY);
      expect(mockFetch).toHaveBeenCalledTimes(3);
      // Delay called for attempts 0 and 1, not for last attempt
      expect(delaySpy).toHaveBeenCalledTimes(2);
    });

    it('retries on 429 with Retry-After header', async () => {
      mockFetch
        .mockResolvedValueOnce(createMockResponse(429, { headers: { 'Retry-After': '2' } }))
        .mockResolvedValueOnce(createMockResponse(200));

      await client.publish(ipnsName, recordBytes);

      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(delaySpy).toHaveBeenCalledWith(2000); // 2 seconds from Retry-After
    });

    it('skips sleeping on 429 on last retry attempt', async () => {
      mockFetch.mockResolvedValue(createMockResponse(429, { headers: { 'Retry-After': '5' } }));

      const error = await client.publish(ipnsName, recordBytes).catch((e) => e);

      expect(error).toBeInstanceOf(HttpException);
      expect(mockFetch).toHaveBeenCalledTimes(3);
      // Should only delay for first 2 attempts, skip delay on last
      expect(delaySpy).toHaveBeenCalledTimes(2);
    });

    it('uses abort signal for timeout', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(200));

      await client.publish(ipnsName, recordBytes);

      const [, init] = mockFetch.mock.calls[0];
      expect(init.signal).toBeInstanceOf(AbortSignal);
    });
  });

  describe('resolve', () => {
    const ipnsName = 'k51qzi5uqu5dg12345';
    const testBuffer = new Uint8Array([10, 20, 30]).buffer;

    function okResponse() {
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: jest.fn().mockResolvedValue(testBuffer),
      } as unknown as Response;
    }

    it('resolves successfully and returns Uint8Array', async () => {
      mockFetch.mockResolvedValueOnce(okResponse());

      const result = await client.resolve(ipnsName);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe(
        `https://routing.example.com/routing/v1/ipns/${encodeURIComponent(ipnsName)}`
      );
      expect(init.method).toBe('GET');
      expect(init.headers.Accept).toBe('application/vnd.ipfs.ipns-record');
    });

    it('returns null for 404 (IPNS name not found)', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(404));

      const result = await client.resolve(ipnsName);

      expect(result).toBeNull();
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('throws BAD_GATEWAY on non-retryable HTTP error', async () => {
      mockFetch.mockResolvedValue(createMockResponse(500, { body: 'error' }));

      const error = await client.resolve(ipnsName).catch((e) => e);

      expect(error).toBeInstanceOf(HttpException);
      expect(error.getStatus()).toBe(HttpStatus.BAD_GATEWAY);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('retries on network errors', async () => {
      mockFetch
        .mockRejectedValueOnce(new Error('network error'))
        .mockResolvedValueOnce(okResponse());

      const result = await client.resolve(ipnsName);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(delaySpy).toHaveBeenCalledWith(1000);
    });

    it('retries on 429 with Retry-After', async () => {
      mockFetch
        .mockResolvedValueOnce(createMockResponse(429, { headers: { 'Retry-After': '1' } }))
        .mockResolvedValueOnce(okResponse());

      const result = await client.resolve(ipnsName);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(delaySpy).toHaveBeenCalledWith(1000); // 1s from Retry-After
    });

    it('re-throws HttpException without retrying', async () => {
      const httpError = new HttpException('custom error', HttpStatus.FORBIDDEN);
      mockFetch.mockRejectedValueOnce(httpError);

      await expect(client.resolve(ipnsName)).rejects.toThrow(httpError);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('throws BAD_GATEWAY after exhausting retries', async () => {
      mockFetch.mockRejectedValue(new Error('network error'));

      const error = await client.resolve(ipnsName).catch((e) => e);

      expect(error).toBeInstanceOf(HttpException);
      expect(error.getStatus()).toBe(HttpStatus.BAD_GATEWAY);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });

  describe('retry delay capping', () => {
    const ipnsName = 'k51test';
    const recordBytes = new Uint8Array([1]);

    it('caps Retry-After delay at 30 seconds', async () => {
      mockFetch
        .mockResolvedValueOnce(createMockResponse(429, { headers: { 'Retry-After': '999' } }))
        .mockResolvedValueOnce(createMockResponse(200));

      await client.publish(ipnsName, recordBytes);

      expect(delaySpy).toHaveBeenCalledWith(30_000); // capped, not 999000
    });

    it('uses exponential backoff fallback when no Retry-After header', async () => {
      mockFetch
        .mockResolvedValueOnce(createMockResponse(429))
        .mockResolvedValueOnce(createMockResponse(200));

      await client.publish(ipnsName, recordBytes);

      // Fallback for attempt 0: min(1000 * 2^0, 30000) = 1000ms
      expect(delaySpy).toHaveBeenCalledWith(1000);
    });

    it('encodes ipnsName in URL to handle reserved characters', async () => {
      const weirdName = 'k51+special/chars?here';
      mockFetch.mockResolvedValueOnce(createMockResponse(200));

      await client.publish(weirdName, new Uint8Array([1]));

      const [url] = mockFetch.mock.calls[0];
      expect(url).toBe(
        `https://routing.example.com/routing/v1/ipns/${encodeURIComponent(weirdName)}`
      );
      expect(url).not.toContain('?here');
    });

    it('parses HTTP-date Retry-After format', async () => {
      const futureDate = new Date(Date.now() + 5000).toUTCString();
      mockFetch
        .mockResolvedValueOnce(createMockResponse(429, { headers: { 'Retry-After': futureDate } }))
        .mockResolvedValueOnce(createMockResponse(200));

      await client.publish(ipnsName, recordBytes);

      const delayArg = delaySpy.mock.calls[0][0];
      // Should be roughly 5000ms (allow some tolerance for time passing)
      expect(delayArg).toBeGreaterThan(3000);
      expect(delayArg).toBeLessThanOrEqual(30_000);
    });
  });
});
