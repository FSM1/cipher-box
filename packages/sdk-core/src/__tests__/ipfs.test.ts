import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { addToIpfs, fetchFromIpfs, unpinFromIpfs } from '../ipfs';
import { createMockContext } from './helpers';

vi.mock('axios', () => {
  return {
    default: {
      post: vi.fn(),
    },
  };
});

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('IPFS operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('addToIpfs', () => {
    it('uploads data with auth header from context', async () => {
      const ctx = createMockContext();
      const data = new Uint8Array([1, 2, 3, 4]);
      const mockResponse = {
        data: { cid: 'QmTest123', size: 4, recorded: true },
      };
      vi.mocked(axios.post).mockResolvedValue(mockResponse);

      const result = await addToIpfs(ctx, data);

      expect(ctx.getAccessToken).toHaveBeenCalled();
      expect(axios.post).toHaveBeenCalledWith(
        'http://localhost:3000/ipfs/upload',
        expect.any(FormData),
        expect.objectContaining({
          headers: { Authorization: 'Bearer test-token' },
        })
      );
      expect(result).toEqual({
        cid: 'QmTest123',
        size: 4,
        recorded: true,
      });
    });

    it('calls progress callback during upload', async () => {
      const ctx = createMockContext();
      const data = new Uint8Array([1, 2, 3]);
      const onProgress = vi.fn();

      vi.mocked(axios.post).mockImplementation(async (_url, _data, config) => {
        // Simulate upload progress
        if (config?.onUploadProgress) {
          config.onUploadProgress({ loaded: 50, total: 100 } as never);
          config.onUploadProgress({ loaded: 100, total: 100 } as never);
        }
        return { data: { cid: 'QmTest', size: 3, recorded: true } };
      });

      await addToIpfs(ctx, data, onProgress);

      expect(onProgress).toHaveBeenCalledWith(50);
      expect(onProgress).toHaveBeenCalledWith(100);
    });
  });

  describe('unpinFromIpfs', () => {
    it('sends unpin request with correct CID and auth header', async () => {
      const ctx = createMockContext();
      vi.mocked(axios.post).mockResolvedValue({});

      await unpinFromIpfs(ctx, 'QmCidToUnpin');

      expect(axios.post).toHaveBeenCalledWith(
        'http://localhost:3000/ipfs/unpin',
        { cid: 'QmCidToUnpin' },
        { headers: { Authorization: 'Bearer test-token' } }
      );
    });
  });

  describe('fetchFromIpfs', () => {
    it('fetches data with auth header and returns Uint8Array', async () => {
      const ctx = createMockContext();
      const mockData = new Uint8Array([10, 20, 30]);

      mockFetch.mockResolvedValue({
        ok: true,
        headers: { get: () => null },
        arrayBuffer: () => Promise.resolve(mockData.buffer),
      });

      const result = await fetchFromIpfs(ctx, 'QmFetchCid');

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:3000/ipfs/QmFetchCid', {
        headers: { Authorization: 'Bearer test-token' },
      });
      expect(result).toBeInstanceOf(Uint8Array);
    });

    it('throws on non-OK response', async () => {
      const ctx = createMockContext();

      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
      });

      await expect(fetchFromIpfs(ctx, 'QmNotFound')).rejects.toThrow(
        'Failed to fetch from IPFS: 404'
      );
    });
  });
});
