import {
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { LocalProvider } from './local.provider';

describe('LocalProvider', () => {
  let provider: LocalProvider;
  let mockFetch: jest.Mock;
  const API_URL = 'http://localhost:5001';
  const GATEWAY_URL = 'http://localhost:8080';

  beforeEach(() => {
    mockFetch = jest.fn();
    global.fetch = mockFetch;
    provider = new LocalProvider(API_URL, GATEWAY_URL);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('constructor', () => {
    it('should throw if API URL is not provided', () => {
      expect(() => new LocalProvider('', GATEWAY_URL)).toThrow('IPFS API URL is required');
    });

    it('should create provider with valid URLs', () => {
      const instance = new LocalProvider(API_URL, GATEWAY_URL);
      expect(instance).toBeInstanceOf(LocalProvider);
    });
  });

  describe('pinFile', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSize = '1024';
    const testBuffer = Buffer.from('test encrypted content');

    it('should return cid and size on successful pin', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            Hash: mockCid,
            Name: 'file-123',
            Size: mockSize,
          }),
      });

      const result = await provider.pinFile(testBuffer);

      expect(result).toEqual({ cid: mockCid, size: parseInt(mockSize, 10) });
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should use POST method for Kubo API', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            Hash: mockCid,
            Name: 'file-123',
            Size: mockSize,
          }),
      });

      await provider.pinFile(testBuffer);

      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toContain(`${API_URL}/api/v0/add`);
      expect(options.method).toBe('POST');
    });

    it('should include cid-version=1 in query params', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            Hash: mockCid,
            Name: 'file-123',
            Size: mockSize,
          }),
      });

      await provider.pinFile(testBuffer);

      const [url] = mockFetch.mock.calls[0];
      expect(url).toContain('cid-version=1');
      expect(url).toContain('pin=true');
    });

    it('should throw BadRequestException for empty buffer', async () => {
      const emptyBuffer = Buffer.from('');

      await expect(provider.pinFile(emptyBuffer)).rejects.toThrow(BadRequestException);
      await expect(provider.pinFile(emptyBuffer)).rejects.toThrow('File data cannot be empty');
    });

    it('should throw InternalServerErrorException on Kubo error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Kubo internal error'),
      });

      await expect(provider.pinFile(testBuffer)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.pinFile(testBuffer)).rejects.toThrow('IPFS add failed: 500');
    });

    it('should throw InternalServerErrorException on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network timeout'));

      await expect(provider.pinFile(testBuffer)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.pinFile(testBuffer)).rejects.toThrow('Failed to pin file to IPFS');
    });

    it('should parse Size as integer from Kubo response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            Hash: mockCid,
            Name: 'file-123',
            Size: '2048', // String in Kubo response
          }),
      });

      const result = await provider.pinFile(testBuffer);

      expect(result.size).toBe(2048);
      expect(typeof result.size).toBe('number');
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
    });

    it('should use POST method for Kubo unpin API', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await provider.unpinFile(mockCid);

      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toBe(`${API_URL}/api/v0/pin/rm?arg=${mockCid}`);
      expect(options.method).toBe('POST');
    });

    it('should treat "not pinned" error as success (idempotent)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Error: not pinned or pinned indirectly'),
      });

      // Should not throw - "not pinned" means already unpinned
      await expect(provider.unpinFile(mockCid)).resolves.toBeUndefined();
    });

    it('should throw BadRequestException for empty CID', async () => {
      await expect(provider.unpinFile('')).rejects.toThrow(BadRequestException);
      await expect(provider.unpinFile('')).rejects.toThrow('CID is required');
    });

    it('should throw InternalServerErrorException on other Kubo errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal server error'),
      });

      await expect(provider.unpinFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.unpinFile(mockCid)).rejects.toThrow('IPFS unpin failed: 500');
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
      const contentArrayBuffer = new Uint8Array(mockContent).buffer;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: () => Promise.resolve(contentArrayBuffer),
      });

      const result = await provider.getFile(mockCid);

      expect(result.toString()).toBe(mockContent.toString());
    });

    it('should use POST method for Kubo cat API', async () => {
      const contentArrayBuffer = new Uint8Array(mockContent).buffer;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: () => Promise.resolve(contentArrayBuffer),
      });

      await provider.getFile(mockCid);

      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toBe(`${API_URL}/api/v0/cat?arg=${mockCid}`);
      expect(options.method).toBe('POST');
    });

    it('should throw NotFoundException for "not found" error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Error: not found'),
      });

      await expect(provider.getFile(mockCid)).rejects.toThrow(NotFoundException);
      await expect(provider.getFile(mockCid)).rejects.toThrow(`File not found: ${mockCid}`);
    });

    it('should throw NotFoundException for "no link" error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Error: no link named'),
      });

      await expect(provider.getFile(mockCid)).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException for "blockstore: block not found" error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('blockstore: block not found'),
      });

      await expect(provider.getFile(mockCid)).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException for empty CID', async () => {
      await expect(provider.getFile('')).rejects.toThrow(BadRequestException);
      await expect(provider.getFile('')).rejects.toThrow('CID is required');
    });

    it('should throw InternalServerErrorException on Kubo error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal server error'),
      });

      await expect(provider.getFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.getFile(mockCid)).rejects.toThrow('IPFS cat failed: 500');
    });

    it('should throw InternalServerErrorException on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network timeout'));

      await expect(provider.getFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(provider.getFile(mockCid)).rejects.toThrow('Failed to get file from IPFS');
    });
  });
});
