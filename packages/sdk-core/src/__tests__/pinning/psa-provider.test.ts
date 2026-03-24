import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PsaProvider } from '../../pinning/psa-provider';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('PsaProvider', () => {
  const endpoint = 'https://api.pinata.cloud';
  const authToken = 'test-psa-token';
  let provider: PsaProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new PsaProvider(endpoint, authToken);
  });

  describe('pin()', () => {
    it('throws Error saying PSA cannot upload raw data', async () => {
      await expect(provider.pin(new Uint8Array([1, 2, 3]))).rejects.toThrow(
        'cannot upload raw data'
      );
    });
  });

  describe('pinByCid()', () => {
    it('sends POST /pins with Bearer auth and JSON body { cid, name }', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            requestid: 'req-abc',
            status: 'queued',
            pin: { cid: 'bafyPinned123', name: 'my-file' },
          }),
      });

      const result = await provider.pinByCid('bafyPinned123', 'my-file');

      expect(result).toEqual({ cid: 'bafyPinned123', status: 'queued' });

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[0]).toBe(`${endpoint}/pins`);
      expect(callArgs[1].method).toBe('POST');
      expect(callArgs[1].headers).toEqual(
        expect.objectContaining({
          Authorization: `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        })
      );
      const body = JSON.parse(callArgs[1].body);
      expect(body.cid).toBe('bafyPinned123');
      expect(body.name).toBe('my-file');
    });

    it('uses default name when none provided', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            requestid: 'req-def',
            status: 'pinning',
            pin: { cid: 'bafyDefault' },
          }),
      });

      await provider.pinByCid('bafyDefault');

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.name).toMatch(/^cipherbox-\d+$/);
    });

    it('throws on non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        text: () => Promise.resolve('invalid cid'),
      });

      await expect(provider.pinByCid('invalid')).rejects.toThrow('PSA pin failed: 400');
    });
  });

  describe('unpin()', () => {
    it('first lists pins by CID, then deletes each by requestid', async () => {
      // First call: list pins by CID
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            count: 1,
            results: [{ requestid: 'req-1', status: 'pinned', pin: { cid: 'bafyUnpin' } }],
          }),
      });

      // Second call: delete by requestid
      mockFetch.mockResolvedValueOnce({ ok: true });

      await provider.unpin('bafyUnpin');

      expect(mockFetch).toHaveBeenCalledTimes(2);

      // First call: GET /pins?cid=...&status=pinned,pinning,queued
      const listCall = mockFetch.mock.calls[0];
      expect(listCall[0]).toContain('/pins?cid=bafyUnpin&status=pinned,pinning,queued');
      expect(listCall[1].method).toBe('GET');

      // Second call: DELETE /pins/req-1
      const deleteCall = mockFetch.mock.calls[1];
      expect(deleteCall[0]).toBe(`${endpoint}/pins/req-1`);
      expect(deleteCall[1].method).toBe('DELETE');
    });

    it('handles multiple pin requests for same CID', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            count: 2,
            results: [
              { requestid: 'req-a', status: 'pinned', pin: { cid: 'bafyMulti' } },
              { requestid: 'req-b', status: 'queued', pin: { cid: 'bafyMulti' } },
            ],
          }),
      });
      mockFetch.mockResolvedValueOnce({ ok: true });
      mockFetch.mockResolvedValueOnce({ ok: true });

      await provider.unpin('bafyMulti');

      // 1 list + 2 deletes = 3 total calls
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('includes Bearer auth on all requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ count: 0, results: [] }),
      });

      await provider.unpin('bafyAuth');

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers).toEqual(expect.objectContaining({ Authorization: `Bearer ${authToken}` }));
    });
  });

  describe('status()', () => {
    it('queries GET /pins?cid={cid}&limit=1 and maps PSA status', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            count: 1,
            results: [{ requestid: 'req-s1', status: 'pinned', pin: { cid: 'bafyStat' } }],
          }),
      });

      const result = await provider.status('bafyStat');

      expect(result).toEqual({ cid: 'bafyStat', status: 'pinned' });
      expect(mockFetch.mock.calls[0][0]).toContain('/pins?cid=bafyStat&limit=1');
      expect(mockFetch.mock.calls[0][1].method).toBe('GET');
    });

    it('returns { status: "failed" } when count is 0', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ count: 0, results: [] }),
      });

      const result = await provider.status('bafyNotExist');

      expect(result).toEqual({ cid: 'bafyNotExist', status: 'failed' });
    });

    it('returns { status: "failed" } on non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
      });

      const result = await provider.status('bafyErr');

      expect(result).toEqual({ cid: 'bafyErr', status: 'failed' });
    });
  });

  describe('get()', () => {
    it('throws Error saying PSA does not support content retrieval', async () => {
      await expect(provider.get('bafyAny')).rejects.toThrow('does not support content retrieval');
    });
  });
});
