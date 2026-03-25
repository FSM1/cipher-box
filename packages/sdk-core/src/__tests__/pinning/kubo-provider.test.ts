import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KuboProvider } from '../../pinning/kubo-provider';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('KuboProvider', () => {
  const endpoint = 'http://localhost:5001';
  let provider: KuboProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new KuboProvider(endpoint);
  });

  describe('pin()', () => {
    it('sends FormData to /api/v0/add?pin=true&cid-version=1 and returns { cid, size }', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(JSON.stringify({ Hash: 'bafyabc123', Size: '1234' })),
      });

      const data = new Uint8Array([1, 2, 3, 4]);
      const result = await provider.pin(data);

      expect(mockFetch).toHaveBeenCalledWith(
        `${endpoint}/api/v0/add?pin=true&cid-version=1`,
        expect.objectContaining({
          method: 'POST',
          body: expect.any(FormData),
        })
      );
      expect(result).toEqual({ cid: 'bafyabc123', size: 1234 });
    });

    it('includes Basic auth header when authToken is provided', async () => {
      const authedProvider = new KuboProvider(endpoint, 'my-secret-token');
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(JSON.stringify({ Hash: 'bafyxyz', Size: '42' })),
      });

      await authedProvider.pin(new Uint8Array([5, 6]));

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1].headers).toEqual(
        expect.objectContaining({
          Authorization: 'Basic my-secret-token',
        })
      );
    });

    it('throws on non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('internal server error'),
      });

      await expect(provider.pin(new Uint8Array([1]))).rejects.toThrow('Kubo add failed: 500');
    });
  });

  describe('unpin()', () => {
    it('sends POST to /api/v0/pin/rm?arg={cid}', async () => {
      mockFetch.mockResolvedValue({ ok: true });

      await provider.unpin('bafyToRemove');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v0/pin/rm?arg=bafyToRemove'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('ignores "not pinned" error in response body', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('pin is not pinned'),
      });

      // Should not throw
      await expect(provider.unpin('bafyNotPinned')).resolves.toBeUndefined();
    });

    it('throws on other non-ok responses', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('something went wrong'),
      });

      await expect(provider.unpin('bafyError')).rejects.toThrow('Kubo unpin failed: 500');
    });
  });

  describe('status()', () => {
    it('returns { status: "pinned" } on successful response', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ Keys: { bafyPinned: { Type: 'recursive' } } }),
      });

      const result = await provider.status('bafyPinned');

      expect(result).toEqual({ cid: 'bafyPinned', status: 'pinned' });
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v0/pin/ls?arg=bafyPinned'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('returns { status: "failed" } on error response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('not found'),
      });

      const result = await provider.status('bafyNotFound');

      expect(result).toEqual({ cid: 'bafyNotFound', status: 'failed' });
    });

    it('returns { status: "failed" } when fetch throws', async () => {
      mockFetch.mockRejectedValue(new Error('network error'));

      const result = await provider.status('bafyNetErr');

      expect(result).toEqual({ cid: 'bafyNetErr', status: 'failed' });
    });
  });

  describe('get()', () => {
    it('returns Uint8Array from /api/v0/cat?arg={cid}', async () => {
      const testBytes = new Uint8Array([10, 20, 30, 40]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(testBytes.buffer),
      });

      const result = await provider.get('bafyCatMe');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v0/cat?arg=bafyCatMe'),
        expect.objectContaining({ method: 'POST' })
      );
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result).toEqual(testBytes);
    });

    it('throws on non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        text: () => Promise.resolve('block not found'),
      });

      await expect(provider.get('bafyMissing')).rejects.toThrow('Kubo cat failed: 404');
    });
  });

  describe('endpoint normalization', () => {
    it('strips trailing slash from endpoint', async () => {
      const slashProvider = new KuboProvider('http://localhost:5001/');
      mockFetch.mockResolvedValue({ ok: true });

      await slashProvider.unpin('bafyTest');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('http://localhost:5001/api/v0/pin/rm'),
        expect.anything()
      );
      // Ensure no double slash
      expect(mockFetch.mock.calls[0][0]).not.toContain('//api');
    });
  });
});
