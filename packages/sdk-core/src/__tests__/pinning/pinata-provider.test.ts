import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PinataProvider } from '../../pinning/pinata-provider';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('PinataProvider', () => {
  const endpoint = 'https://api.pinata.cloud';
  const authToken = 'test-pinata-jwt';
  const gatewayUrl = 'https://mygateway.mypinata.cloud';
  let provider: PinataProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new PinataProvider(endpoint, authToken, gatewayUrl);
  });

  describe('pin()', () => {
    it('uploads file via POST /v3/files to uploads.pinata.cloud and returns CID + size', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            data: { id: 'file-123', cid: 'bafyPinataUpload', size: 1024 },
          }),
      });

      const data = new Uint8Array([1, 2, 3, 4]);
      const result = await provider.pin(data, 'test-file');

      expect(result).toEqual({ cid: 'bafyPinataUpload', size: 1024 });

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[0]).toBe('https://uploads.pinata.cloud/v3/files');
      expect(callArgs[1].method).toBe('POST');
    });

    it('includes Bearer auth token in header', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            data: { id: 'file-456', cid: 'bafyAuth', size: 512 },
          }),
      });

      await provider.pin(new Uint8Array([1]), 'auth-test');

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1].headers).toEqual(
        expect.objectContaining({
          Authorization: `Bearer ${authToken}`,
        })
      );
    });

    it('throws on non-200 response with descriptive error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        text: () => Promise.resolve('invalid jwt token'),
      });

      await expect(provider.pin(new Uint8Array([1]))).rejects.toThrow(
        'Pinata upload failed: 401 - invalid jwt token'
      );
    });
  });

  describe('unpin()', () => {
    it('calls DELETE /v3/files/{id} after looking up file by CID', async () => {
      // First call: list files by CID
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            data: { files: [{ id: 'file-to-delete', cid: 'bafyUnpin', size: 256 }] },
          }),
      });

      // Second call: delete by id
      mockFetch.mockResolvedValueOnce({ ok: true });

      await provider.unpin('bafyUnpin');

      expect(mockFetch).toHaveBeenCalledTimes(2);

      // First call: GET /v3/files?cid=...
      const listCall = mockFetch.mock.calls[0];
      expect(listCall[0]).toBe(`${endpoint}/v3/files?cid=bafyUnpin`);
      expect(listCall[1].method).toBe('GET');
      expect(listCall[1].headers).toEqual(
        expect.objectContaining({ Authorization: `Bearer ${authToken}` })
      );

      // Second call: DELETE /v3/files/file-to-delete
      const deleteCall = mockFetch.mock.calls[1];
      expect(deleteCall[0]).toBe(`${endpoint}/v3/files/file-to-delete`);
      expect(deleteCall[1].method).toBe('DELETE');
    });

    it('handles multiple files for same CID', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            data: {
              files: [
                { id: 'file-a', cid: 'bafyMulti', size: 100 },
                { id: 'file-b', cid: 'bafyMulti', size: 200 },
              ],
            },
          }),
      });
      mockFetch.mockResolvedValueOnce({ ok: true });
      mockFetch.mockResolvedValueOnce({ ok: true });

      await provider.unpin('bafyMulti');

      // 1 list + 2 deletes = 3 total calls
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });

  describe('status()', () => {
    it('returns pinned status for existing CID', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            data: { files: [{ id: 'file-status', cid: 'bafyStat' }] },
          }),
      });

      const result = await provider.status('bafyStat');

      expect(result).toEqual({ cid: 'bafyStat', status: 'pinned' });
      expect(mockFetch.mock.calls[0][0]).toBe(`${endpoint}/v3/files?cid=bafyStat`);
      expect(mockFetch.mock.calls[0][1].method).toBe('GET');
    });

    it('returns failed status for unknown CID', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            data: { files: [] },
          }),
      });

      const result = await provider.status('bafyNotFound');

      expect(result).toEqual({ cid: 'bafyNotFound', status: 'failed' });
    });

    it('returns failed status on non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
      });

      const result = await provider.status('bafyErr');

      expect(result).toEqual({ cid: 'bafyErr', status: 'failed' });
    });
  });

  describe('get()', () => {
    it('fetches content via Pinata dedicated gateway', async () => {
      const fileContent = new Uint8Array([10, 20, 30]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(fileContent.buffer),
      });

      const result = await provider.get('bafyGet');

      expect(result).toEqual(fileContent);
      expect(mockFetch.mock.calls[0][0]).toBe(`${gatewayUrl}/ipfs/bafyGet`);
    });

    it('uses default gateway when no custom gateway configured', async () => {
      const defaultProvider = new PinataProvider(endpoint, authToken);
      const fileContent = new Uint8Array([5, 6, 7]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(fileContent.buffer),
      });

      await defaultProvider.get('bafyDefault');

      expect(mockFetch.mock.calls[0][0]).toBe('https://gateway.pinata.cloud/ipfs/bafyDefault');
    });

    it('throws on non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
      });

      await expect(provider.get('bafyMissing')).rejects.toThrow('Pinata gateway fetch failed: 404');
    });
  });

  describe('pinByCid()', () => {
    it('pins an existing CID via /pinning/pinByHash', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            ipfsHash: 'bafyExisting',
            status: 'searching',
          }),
      });

      const result = await provider.pinByCid('bafyExisting');

      expect(result).toEqual({ cid: 'bafyExisting', status: 'searching' });

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[0]).toBe(`${endpoint}/pinning/pinByHash`);
      expect(callArgs[1].method).toBe('POST');
      expect(callArgs[1].headers).toEqual(
        expect.objectContaining({
          Authorization: `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        })
      );
      const body = JSON.parse(callArgs[1].body);
      expect(body.hashToPin).toBe('bafyExisting');
    });

    it('throws on non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        text: () => Promise.resolve('invalid hash'),
      });

      await expect(provider.pinByCid('invalid')).rejects.toThrow(
        'Pinata pinByHash failed: 400 - invalid hash'
      );
    });
  });
});
