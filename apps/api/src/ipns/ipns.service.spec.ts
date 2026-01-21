import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, HttpException, HttpStatus } from '@nestjs/common';
import { IpnsService } from './ipns.service';
import { FolderIpns } from './entities/folder-ipns.entity';
import { PublishIpnsDto } from './dto';
import { User } from '../auth/entities/user.entity';

describe('IpnsService', () => {
  let service: IpnsService;
  let mockFolderIpnsRepo: {
    findOne: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
  };
  let mockConfigService: {
    get: jest.Mock;
  };

  // Test data
  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testIpnsName = 'k51qzi5uqu5dg12345abcdef67890';
  const testMetadataCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
  const testRecord = btoa('test-ipns-record-bytes'); // base64 encoded
  const testEncryptedIpnsPrivateKey = 'a'.repeat(128); // 64 bytes hex
  const testKeyEpoch = 1;
  const testDelegatedRoutingUrl = 'https://test-delegated.example.com';

  const mockFolderEntity: FolderIpns = {
    id: 'folder-id-1',
    userId: testUserId,
    ipnsName: testIpnsName,
    latestCid: testMetadataCid,
    sequenceNumber: '5',
    encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
    keyEpoch: testKeyEpoch,
    isRoot: false,
    createdAt: new Date('2026-01-20T12:00:00.000Z'),
    updatedAt: new Date('2026-01-20T12:00:00.000Z'),
    user: {} as User,
  };

  // Mock fetch
  const mockFetch = jest.fn();

  beforeEach(async () => {
    // Reset fetch mock
    mockFetch.mockReset();
    global.fetch = mockFetch;

    mockFolderIpnsRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
    };

    mockConfigService = {
      get: jest.fn().mockImplementation((key: string, defaultValue?: string) => {
        if (key === 'DELEGATED_ROUTING_URL') {
          return testDelegatedRoutingUrl;
        }
        return defaultValue;
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IpnsService,
        {
          provide: getRepositoryToken(FolderIpns),
          useValue: mockFolderIpnsRepo,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<IpnsService>(IpnsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should use delegated routing URL from config', () => {
      expect(mockConfigService.get).toHaveBeenCalledWith(
        'DELEGATED_ROUTING_URL',
        'https://delegated-ipfs.dev'
      );
    });
  });

  describe('publishRecord', () => {
    const createDto = (overrides?: Partial<PublishIpnsDto>): PublishIpnsDto => ({
      ipnsName: testIpnsName,
      record: testRecord,
      metadataCid: testMetadataCid,
      encryptedIpnsPrivateKey: testEncryptedIpnsPrivateKey,
      keyEpoch: testKeyEpoch,
      ...overrides,
    });

    it('should publish record for new folder successfully', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '0' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '0' });

      const result = await service.publishRecord(testUserId, createDto());

      expect(result.success).toBe(true);
      expect(result.ipnsName).toBe(testIpnsName);
      expect(result.sequenceNumber).toBe('0');
      expect(mockFetch).toHaveBeenCalledWith(
        `${testDelegatedRoutingUrl}/routing/v1/ipns/${testIpnsName}`,
        expect.objectContaining({
          method: 'PUT',
          headers: { 'Content-Type': 'application/vnd.ipfs.ipns-record' },
        })
      );
    });

    it('should publish record for existing folder and increment sequence', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '6' });

      const result = await service.publishRecord(
        testUserId,
        createDto({ encryptedIpnsPrivateKey: undefined, keyEpoch: undefined })
      );

      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe('6');
    });

    it('should throw BadRequestException for invalid base64 record', async () => {
      const invalidDto = createDto({ record: '!!!invalid-base64!!!' });

      await expect(service.publishRecord(testUserId, invalidDto)).rejects.toThrow(
        BadRequestException
      );
      await expect(service.publishRecord(testUserId, invalidDto)).rejects.toThrow(
        'Invalid base64-encoded record'
      );
    });

    it('should throw BadRequestException if encryptedIpnsPrivateKey missing for new folder', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const dto = createDto({ encryptedIpnsPrivateKey: undefined });

      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(BadRequestException);
      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(
        'encryptedIpnsPrivateKey is required for first publish of a folder'
      );
    });

    it('should throw BadRequestException if keyEpoch missing for new folder', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const dto = createDto({ keyEpoch: undefined });

      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(BadRequestException);
      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(
        'keyEpoch is required for first publish of a folder'
      );
    });

    it('should throw HttpException on delegated routing failure', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });

      await expect(service.publishRecord(testUserId, createDto())).rejects.toThrow(HttpException);
      await expect(service.publishRecord(testUserId, createDto())).rejects.toThrow(
        'Failed to publish IPNS record to routing network'
      );
    });

    it('should retry on rate limiting (429) with Retry-After header', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: () => '1' }, // 1 second retry
        })
        .mockResolvedValueOnce({ ok: true });
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);

      // Mock delay to speed up test
      jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
        cb();
        return 0 as unknown as NodeJS.Timeout;
      });

      const result = await service.publishRecord(testUserId, createDto());

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should retry on rate limiting (429) without Retry-After header', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: () => null }, // No Retry-After
        })
        .mockResolvedValueOnce({ ok: true });
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);

      jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
        cb();
        return 0 as unknown as NodeJS.Timeout;
      });

      const result = await service.publishRecord(testUserId, createDto());

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should retry on network errors with exponential backoff', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({ ok: true });
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);

      jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
        cb();
        return 0 as unknown as NodeJS.Timeout;
      });

      const result = await service.publishRecord(testUserId, createDto());

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should throw HttpException after max retries on network errors', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFetch.mockRejectedValue(new Error('Network error'));

      jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
        cb();
        return 0 as unknown as NodeJS.Timeout;
      });

      await expect(service.publishRecord(testUserId, createDto())).rejects.toThrow(HttpException);
      await expect(service.publishRecord(testUserId, createDto())).rejects.toThrow(
        'Failed to publish IPNS record to routing network after multiple attempts'
      );
    });

    it('should update encrypted key on key rotation for existing folder', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity });
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));

      const newKeyEpoch = 2;
      const newEncryptedKey = 'b'.repeat(128);

      await service.publishRecord(
        testUserId,
        createDto({
          encryptedIpnsPrivateKey: newEncryptedKey,
          keyEpoch: newKeyEpoch,
        })
      );

      expect(mockFolderIpnsRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          keyEpoch: newKeyEpoch,
          encryptedIpnsPrivateKey: Buffer.from(newEncryptedKey, 'hex'),
        })
      );
    });

    it('should not update encrypted key if only keyEpoch is provided', async () => {
      const originalEntity = { ...mockFolderEntity };
      mockFolderIpnsRepo.findOne.mockResolvedValue(originalEntity);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));

      await service.publishRecord(
        testUserId,
        createDto({
          encryptedIpnsPrivateKey: undefined,
          keyEpoch: 2,
        })
      );

      // When encryptedIpnsPrivateKey is undefined, keyEpoch should not be updated either
      expect(mockFolderIpnsRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          keyEpoch: testKeyEpoch, // Original value preserved
        })
      );
    });
  });

  describe('getFolderIpns', () => {
    it('should return folder entry when found', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);

      const result = await service.getFolderIpns(testUserId, testIpnsName);

      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalledWith({
        where: { userId: testUserId, ipnsName: testIpnsName },
      });
      expect(result).toEqual(mockFolderEntity);
    });

    it('should return null when folder not found', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const result = await service.getFolderIpns(testUserId, testIpnsName);

      expect(result).toBeNull();
    });
  });

  describe('getAllFolderIpns', () => {
    it('should return all folder entries for user', async () => {
      const folders = [
        mockFolderEntity,
        { ...mockFolderEntity, id: 'folder-id-2', ipnsName: 'k51another' },
      ];
      mockFolderIpnsRepo.find.mockResolvedValue(folders);

      const result = await service.getAllFolderIpns(testUserId);

      expect(mockFolderIpnsRepo.find).toHaveBeenCalledWith({
        where: { userId: testUserId },
        order: { createdAt: 'ASC' },
      });
      expect(result).toEqual(folders);
      expect(result).toHaveLength(2);
    });

    it('should return empty array when user has no folders', async () => {
      mockFolderIpnsRepo.find.mockResolvedValue([]);

      const result = await service.getAllFolderIpns(testUserId);

      expect(result).toEqual([]);
    });
  });

  describe('upsertFolderIpns (tested through publishRecord)', () => {
    it('should create new folder with correct fields', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.create.mockReturnValue({
        userId: testUserId,
        ipnsName: testIpnsName,
        latestCid: testMetadataCid,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
        keyEpoch: testKeyEpoch,
        isRoot: false,
      });
      mockFolderIpnsRepo.save.mockImplementation((entity) =>
        Promise.resolve({ ...entity, id: 'new-id' })
      );

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
        encryptedIpnsPrivateKey: testEncryptedIpnsPrivateKey,
        keyEpoch: testKeyEpoch,
      });

      expect(mockFolderIpnsRepo.create).toHaveBeenCalledWith({
        userId: testUserId,
        ipnsName: testIpnsName,
        latestCid: testMetadataCid,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
        keyEpoch: testKeyEpoch,
        isRoot: false,
      });
    });

    it('should increment sequence number for existing folder', async () => {
      const existingFolder = { ...mockFolderEntity, sequenceNumber: '10' };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingFolder);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: 'new-cid',
      });

      expect(mockFolderIpnsRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          sequenceNumber: '11',
          latestCid: 'new-cid',
        })
      );
    });

    it('should handle BigInt sequence number correctly', async () => {
      const largeSeqFolder = {
        ...mockFolderEntity,
        sequenceNumber: '9007199254740991', // MAX_SAFE_INTEGER
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(largeSeqFolder);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: 'new-cid',
      });

      expect(mockFolderIpnsRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          sequenceNumber: '9007199254740992', // MAX_SAFE_INTEGER + 1
        })
      );
    });

    it('should update timestamp on existing folder update', async () => {
      const existingFolder = {
        ...mockFolderEntity,
        updatedAt: new Date('2020-01-01'),
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingFolder);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));

      const beforeTest = new Date();
      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: 'new-cid',
      });
      const afterTest = new Date();

      const savedEntity = mockFolderIpnsRepo.save.mock.calls[0][0];
      expect(savedEntity.updatedAt.getTime()).toBeGreaterThanOrEqual(beforeTest.getTime());
      expect(savedEntity.updatedAt.getTime()).toBeLessThanOrEqual(afterTest.getTime());
    });
  });

  describe('error handling in publishToDelegatedRouting', () => {
    beforeEach(() => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
        cb();
        return 0 as unknown as NodeJS.Timeout;
      });
    });

    it('should convert non-Error exceptions to Error objects', async () => {
      mockFetch.mockRejectedValue('string error');

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).rejects.toThrow(HttpException);
    });

    it('should throw BAD_GATEWAY for non-429 HTTP errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        text: () => Promise.resolve('Bad Request'),
      });

      try {
        await service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        });
        fail('Expected HttpException to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect((error as HttpException).getStatus()).toBe(HttpStatus.BAD_GATEWAY);
      }
    });

    it('should throw with generic message to avoid leaking internal details', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 503,
        text: () => Promise.resolve('Sensitive internal error details'),
      });

      try {
        await service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        });
        fail('Expected HttpException to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        const message = (error as HttpException).message;
        expect(message).not.toContain('Sensitive');
        expect(message).toBe('Failed to publish IPNS record to routing network');
      }
    });
  });
});
