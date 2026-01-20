import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { IpfsService } from './ipfs.service';

describe('IpfsService', () => {
  let service: IpfsService;
  let mockFetch: jest.Mock;
  const MOCK_JWT = 'test-pinata-jwt-token';

  beforeEach(async () => {
    // Mock global fetch
    mockFetch = jest.fn();
    global.fetch = mockFetch;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IpfsService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'PINATA_JWT') return MOCK_JWT;
              return undefined;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<IpfsService>(IpfsService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('constructor', () => {
    it('should throw if PINATA_JWT is not configured', async () => {
      await expect(
        Test.createTestingModule({
          providers: [
            IpfsService,
            {
              provide: ConfigService,
              useValue: {
                get: jest.fn(() => undefined),
              },
            },
          ],
        }).compile()
      ).rejects.toThrow('PINATA_JWT environment variable is required');
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

      const result = await service.pinFile(testBuffer);

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

      await service.pinFile(testBuffer);

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1].headers.Authorization).toBe(`Bearer ${MOCK_JWT}`);
    });

    it('should throw BadRequestException for empty file', async () => {
      const emptyBuffer = Buffer.from('');

      await expect(service.pinFile(emptyBuffer)).rejects.toThrow(BadRequestException);
      await expect(service.pinFile(emptyBuffer)).rejects.toThrow('File data cannot be empty');
    });

    it('should throw InternalServerErrorException on Pinata error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Pinata internal error'),
      });

      await expect(service.pinFile(testBuffer)).rejects.toThrow(InternalServerErrorException);
      await expect(service.pinFile(testBuffer)).rejects.toThrow('Pinata upload failed: 500');
    });

    it('should throw InternalServerErrorException on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network timeout'));

      await expect(service.pinFile(testBuffer)).rejects.toThrow(InternalServerErrorException);
      await expect(service.pinFile(testBuffer)).rejects.toThrow('Failed to pin file to IPFS');
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

      await service.pinFile(testBuffer, { userId: 'user-123' });

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

      await expect(service.unpinFile(mockCid)).resolves.toBeUndefined();
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
      await expect(service.unpinFile(mockCid)).resolves.toBeUndefined();
    });

    it('should throw BadRequestException for empty CID', async () => {
      await expect(service.unpinFile('')).rejects.toThrow(BadRequestException);
      await expect(service.unpinFile('')).rejects.toThrow('CID is required');
    });

    it('should throw InternalServerErrorException on Pinata error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Pinata internal error'),
      });

      await expect(service.unpinFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(service.unpinFile(mockCid)).rejects.toThrow('Pinata unpin failed: 500');
    });

    it('should throw InternalServerErrorException on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network timeout'));

      await expect(service.unpinFile(mockCid)).rejects.toThrow(InternalServerErrorException);
      await expect(service.unpinFile(mockCid)).rejects.toThrow('Failed to unpin file from IPFS');
    });
  });
});
