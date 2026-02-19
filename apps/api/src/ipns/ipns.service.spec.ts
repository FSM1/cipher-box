import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, HttpException, HttpStatus } from '@nestjs/common';
import { IpnsService } from './ipns.service';
import { FolderIpns } from './entities/folder-ipns.entity';
import { PublishIpnsDto } from './dto';
import { User } from '../auth/entities/user.entity';
import { RepublishService } from '../republish/republish.service';
import { parseIpnsRecord } from './ipns-record-parser';

jest.mock('./ipns-record-parser');
const mockParseIpnsRecord = parseIpnsRecord as jest.Mock;

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
        {
          provide: RepublishService,
          useValue: {
            enrollFolder: jest.fn().mockResolvedValue(undefined),
          },
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

    it('should allow publishing without encryptedIpnsPrivateKey for new folder (Phase 6 - TEE optional)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.create.mockReturnValue({
        ...mockFolderEntity,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: null,
        keyEpoch: null,
      });
      mockFolderIpnsRepo.save.mockResolvedValue({
        ...mockFolderEntity,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: null,
        keyEpoch: null,
      });

      const dto = createDto({ encryptedIpnsPrivateKey: undefined, keyEpoch: undefined });

      const result = await service.publishRecord(testUserId, dto);

      expect(result.success).toBe(true);
      expect(mockFolderIpnsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedIpnsPrivateKey: null,
          keyEpoch: null,
        })
      );
    });

    it('should allow publishing without keyEpoch for new folder (Phase 6 - TEE optional)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFetch.mockResolvedValue({ ok: true });
      mockFolderIpnsRepo.create.mockReturnValue({
        ...mockFolderEntity,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
        keyEpoch: null,
      });
      mockFolderIpnsRepo.save.mockResolvedValue({
        ...mockFolderEntity,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
        keyEpoch: null,
      });

      const dto = createDto({ keyEpoch: undefined });

      const result = await service.publishRecord(testUserId, dto);

      expect(result.success).toBe(true);
      expect(mockFolderIpnsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          keyEpoch: null,
        })
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
        recordType: 'folder',
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

  describe('resolveRecord', () => {
    let setTimeoutSpy: jest.SpyInstance;

    beforeEach(() => {
      setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
        cb();
        return 0 as unknown as NodeJS.Timeout;
      });
      mockParseIpnsRecord.mockReset();
    });

    afterEach(() => {
      setTimeoutSpy.mockRestore();
    });

    it('should resolve IPNS name to CID successfully', async () => {
      // Mock fetch returning binary data
      const mockRecordBytes = new Uint8Array([1, 2, 3]); // Placeholder bytes
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      // Mock unmarshalIpnsRecord to return parsed record
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: 5n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi');
      expect(result!.sequenceNumber).toBe('5');
      expect(mockFetch).toHaveBeenCalledWith(
        `${testDelegatedRoutingUrl}/routing/v1/ipns/${testIpnsName}`,
        expect.objectContaining({
          method: 'GET',
          headers: { Accept: 'application/vnd.ipfs.ipns-record' },
        })
      );
    });

    it('should include base64-encoded signature fields when parser returns them', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      const sigBytes = new Uint8Array(64).fill(0xab);
      const dataBytes = new Uint8Array(48).fill(0xcd);
      const pubKeyBytes = new Uint8Array(32).fill(0xef);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: 10n,
        signatureV2: sigBytes,
        data: dataBytes,
        pubKey: pubKeyBytes,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.signatureV2).toBe(Buffer.from(sigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(dataBytes).toString('base64'));
      expect(result!.pubKey).toBe(Buffer.from(pubKeyBytes).toString('base64'));
    });

    it('should omit signature fields when parser does not return them', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: 1n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.signatureV2).toBeUndefined();
      expect(result!.data).toBeUndefined();
      expect(result!.pubKey).toBeUndefined();
    });

    it('should return null for 404 (IPNS name not found)', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).toBeNull();
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should retry on rate limiting (429) with Retry-After header', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: () => '1' },
        })
        .mockResolvedValueOnce({
          ok: true,
          arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
        });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
        sequence: 10n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should retry on rate limiting (429) without Retry-After header', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: () => null },
        })
        .mockResolvedValueOnce({
          ok: true,
          arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
        });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
        sequence: 10n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should return null for non-retryable HTTP errors (500) with no DB cache', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should return null for 400 errors with no DB cache', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        text: () => Promise.resolve('Bad Request'),
      });

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should retry on network errors with exponential backoff', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
        });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: 1n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should return null after max retries on network errors with no DB cache', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should return null for non-Error exceptions during resolve with no DB cache', async () => {
      mockFetch.mockRejectedValue('string error');

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should parse CID from record with Qm prefix (CIDv0)', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG',
        sequence: 1n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG');
    });

    it('should parse CID from record with bafk prefix', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
        sequence: 1n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi');
    });

    it('should return null for invalid record without CID and no DB cache', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockReturnValue({
        value: 'invalid-record-without-cid',
        sequence: 1n,
      });

      // The parsing throws BAD_GATEWAY, which falls through to DB cache → null
      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should extract sequence number from IPNS record', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: 42n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.sequenceNumber).toBe('42');
    });

    it('should default to sequence "0" when not present', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: undefined, // Missing sequence
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.sequenceNumber).toBe('0');
    });

    it('should return null on unmarshal errors with no DB cache', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockImplementation(() => {
        throw new Error('Invalid protobuf');
      });

      // Parse error → BAD_GATEWAY → falls through to DB cache → null
      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should fall back to DB-cached CID when delegated routing returns 502', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED',
        sequenceNumber: '42',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyCACHED');
      expect(result!.sequenceNumber).toBe('42');
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalledWith({
        where: { ipnsName: testIpnsName },
      });
    });

    it('should fall back to DB-cached CID after max retries on network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED2',
        sequenceNumber: '10',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyCACHED2');
      expect(result!.sequenceNumber).toBe('10');
    });

    it('should return null when routing fails and no DB cache exists', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should return null when routing fails and DB cache has no CID', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: null,
      });

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should fall back to DB on parse errors (BAD_GATEWAY)', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockFetch.mockResolvedValue({
        ok: true,
        arrayBuffer: () => Promise.resolve(mockRecordBytes.buffer),
      });
      mockParseIpnsRecord.mockImplementation(() => {
        throw new Error('Invalid protobuf');
      });
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED_PARSE',
        sequenceNumber: '7',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      // Parse error → BAD_GATEWAY → falls through to DB cache
      const result = await service.resolveRecord(testIpnsName);
      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyCACHED_PARSE');
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalled();
    });
  });

  describe('error handling in publishToDelegatedRouting', () => {
    let setTimeoutSpy: jest.SpyInstance;

    beforeEach(() => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
        cb();
        return 0 as unknown as NodeJS.Timeout;
      });
    });

    afterEach(() => {
      setTimeoutSpy.mockRestore();
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
