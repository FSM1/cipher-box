import {
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { PinataProvider } from './pinata.provider';

describe('PinataProvider', () => {
  let provider: PinataProvider;
  let mockFetch: jest.Mock;
  const MOCK_JWT = 'test-pinata-jwt-token';

  beforeEach(() => {
    // Mock global fetch
    mockFetch = jest.fn();
    global.fetch = mockFetch;

    provider = new PinataProvider(MOCK_JWT);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('constructor', () => {
    it('should throw if JWT is not provided', () => {
      expect(() => new PinataProvider('')).toThrow('Pinata JWT is required');
    });
  });

  describe('pinFile', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSize = 1024;
    const testBuffer = Buffer.from('test encrypted content');

    it('should return cid and size on successful pin', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            IpfsHash: mockCid,
            PinSize: mockSize,
            Timestamp: '2026-01-20T00:00:00.000Z',
          }),
      });

      const result = await provider.pinFile(testBuffer);

      expect(result).toEqual({ cid: mockCid, size: mockSize });
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.pinata.cloud/pinning/pinFileToIPFS',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Authorization: `Bearer ${MOCK_JWT}`,
          }),
        })
      );
    });

    it('should include Authorization header in request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            IpfsHash: mockCid,
            PinSize: mockSize,
            Timestamp: '2026-01-20T00:00:00.000Z',
          }),
      });

      await provider.pinFile(testBuffer);

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1].headers.Authorization).toBe(`Bearer ${MOCK_JWT}`);
    });

    it('should throw BadRequestException for empty file', async () => {
      const emptyBuffer = Buffer.from('');

      await expect(provider.pinFile(emptyBuffer)).rejects.toThrow(BadRequestException);
      await expect(provider.pinFile(emptyBuffer)).rejects.toThrow('File data cannot be empty');
    });

    it('should throw InternalServerErrorException on Pinata error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Pinata internal error'),
      });

      await expect(provider.pinFile(testBuffer)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.pinFile(testBuffer)).rejects.toThrow('Pinata upload failed: 500');
    });

    it('should throw InternalServerErrorException on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network timeout'));

      await expect(provider.pinFile(testBuffer)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.pinFile(testBuffer)).rejects.toThrow('Failed to pin file to IPFS');
    });

    it('should include metadata in request when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            IpfsHash: mockCid,
            PinSize: mockSize,
            Timestamp: '2026-01-20T00:00:00.000Z',
          }),
      });

      await provider.pinFile(testBuffer, { userId: 'user-123' });

      // Verify fetch was called (metadata is included in FormData body)
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('unpinFile', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';

    it('should return void on successful unpin', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await expect(provider.unpinFile(mockCid)).resolves.toBeUndefined();
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        `https://api.pinata.cloud/pinning/unpin/${mockCid}`,
        expect.objectContaining({
          method: 'DELETE',
          headers: expect.objectContaining({
            Authorization: `Bearer ${MOCK_JWT}`,
          }),
        })
      );
    });

    it('should handle 404 (already unpinned) gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      // Should not throw - 404 means already unpinned
      await expect(provider.unpinFile(mockCid)).resolves.toBeUndefined();
    });

    it('should throw BadRequestException for empty CID', async () => {
      await expect(provider.unpinFile('')).rejects.toThrow(BadRequestException);
      await expect(provider.unpinFile('')).rejects.toThrow('CID is required');
    });

    it('should throw InternalServerErrorException on Pinata error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Pinata internal error'),
      });

      await expect(provider.unpinFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.unpinFile(mockCid)).rejects.toThrow('Pinata unpin failed: 500');
    });

    it('should throw InternalServerErrorException on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network timeout'));

      await expect(provider.unpinFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.unpinFile(mockCid)).rejects.toThrow('Failed to unpin file from IPFS');
    });
  });

  describe('getFile', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockContent = Buffer.from('encrypted file content');

    it('should return buffer on successful get', async () => {
      // Create a proper ArrayBuffer from the content
      const contentArrayBuffer = new Uint8Array(mockContent).buffer;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: () => Promise.resolve(contentArrayBuffer),
      });

      const result = await provider.getFile(mockCid);

      expect(result.toString()).toBe(mockContent.toString());
      expect(mockFetch).toHaveBeenCalledWith(`https://gateway.pinata.cloud/ipfs/${mockCid}`);
    });

    it('should throw NotFoundException for missing CID', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
      });

      await expect(provider.getFile(mockCid)).rejects.toThrow(NotFoundException);
      await expect(provider.getFile(mockCid)).rejects.toThrow(`File not found: ${mockCid}`);
    });

    it('should throw BadRequestException for empty CID', async () => {
      await expect(provider.getFile('')).rejects.toThrow(BadRequestException);
      await expect(provider.getFile('')).rejects.toThrow('CID is required');
    });

    it('should throw InternalServerErrorException on gateway error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Gateway error'),
      });

      await expect(provider.getFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.getFile(mockCid)).rejects.toThrow('Pinata fetch failed: 500');
    });

    it('should throw InternalServerErrorException on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network timeout'));

      await expect(provider.getFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.getFile(mockCid)).rejects.toThrow('Failed to get file from IPFS');
    });
  });
});
