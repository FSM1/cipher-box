import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { BadRequestException, ConflictException, HttpException, HttpStatus } from '@nestjs/common';
import { IpnsService } from './ipns.service';
import { FolderIpns } from './entities/folder-ipns.entity';
import { PublishIpnsDto, BatchPublishIpnsDto } from './dto';
import { User } from '../auth/entities/user.entity';
import { RepublishService } from '../republish/republish.service';
import { DelegatedRoutingClient } from './delegated-routing.client';
import { MetricsService } from '../metrics/metrics.service';
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
  let mockDelegatedRoutingClient: {
    publish: jest.Mock;
    resolve: jest.Mock;
  };
  let mockEndTimer: jest.Mock;
  let mockStartTimer: jest.Mock;
  let mockMetricsService: {
    ipfsIpnsDuration: { startTimer: jest.Mock };
    ipnsResolveDuration: { observe: jest.Mock };
    ipnsPublishDuration: { observe: jest.Mock };
  };

  // Test data
  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testIpnsName = 'k51qzi5uqu5dg12345abcdef67890';
  const testMetadataCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
  const testRecord = btoa('test-ipns-record-bytes'); // base64 encoded
  const testEncryptedIpnsPrivateKey = 'a'.repeat(128); // 64 bytes hex
  const testKeyEpoch = 1;

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

  beforeEach(async () => {
    mockFolderIpnsRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
    };

    mockDelegatedRoutingClient = {
      publish: jest.fn().mockResolvedValue(undefined),
      resolve: jest.fn().mockResolvedValue(null),
    };

    mockEndTimer = jest.fn();
    mockStartTimer = jest.fn().mockReturnValue(mockEndTimer);
    mockMetricsService = {
      ipfsIpnsDuration: { startTimer: mockStartTimer },
      ipnsResolveDuration: { observe: jest.fn() },
      ipnsPublishDuration: { observe: jest.fn() },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IpnsService,
        {
          provide: getRepositoryToken(FolderIpns),
          useValue: mockFolderIpnsRepo,
        },
        {
          provide: DelegatedRoutingClient,
          useValue: mockDelegatedRoutingClient,
        },
        {
          provide: RepublishService,
          useValue: {
            enrollFolder: jest.fn().mockResolvedValue(undefined),
          },
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
      ],
    }).compile();

    service = module.get<IpnsService>(IpnsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
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
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });

      const result = await service.publishRecord(testUserId, createDto());

      expect(result.success).toBe(true);
      expect(result.ipnsName).toBe(testIpnsName);
      expect(result.sequenceNumber).toBe('1');
      expect(mockDelegatedRoutingClient.publish).toHaveBeenCalledWith(
        testIpnsName,
        expect.any(Uint8Array)
      );
    });

    it('should publish record for existing folder and increment sequence', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
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
      mockFolderIpnsRepo.create.mockReturnValue({
        ...mockFolderEntity,
        sequenceNumber: '1',
        encryptedIpnsPrivateKey: null,
        keyEpoch: null,
      });
      mockFolderIpnsRepo.save.mockResolvedValue({
        ...mockFolderEntity,
        sequenceNumber: '1',
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
      mockFolderIpnsRepo.create.mockReturnValue({
        ...mockFolderEntity,
        sequenceNumber: '1',
        encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
        keyEpoch: null,
      });
      mockFolderIpnsRepo.save.mockResolvedValue({
        ...mockFolderEntity,
        sequenceNumber: '1',
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

    it('should succeed and save to DB even on delegated routing failure', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );

      const result = await service.publishRecord(testUserId, createDto());
      expect(result.success).toBe(true);
      expect(mockFolderIpnsRepo.save).toHaveBeenCalled();
    });

    it('should succeed and save to DB even when delegated routing throws network error', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);
      mockDelegatedRoutingClient.publish.mockRejectedValue(new Error('Network error'));

      const result = await service.publishRecord(testUserId, createDto());
      expect(result.success).toBe(true);
      expect(mockFolderIpnsRepo.save).toHaveBeenCalled();
    });

    it('should update encrypted key on key rotation for existing folder', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity });
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
      mockFolderIpnsRepo.create.mockReturnValue({
        userId: testUserId,
        ipnsName: testIpnsName,
        latestCid: testMetadataCid,
        sequenceNumber: '1',
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
        sequenceNumber: '1',
        encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
        keyEpoch: testKeyEpoch,
        isRoot: false,
        recordType: 'folder',
      });
    });

    it('should increment sequence number for existing folder', async () => {
      const existingFolder = { ...mockFolderEntity, sequenceNumber: '10' };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingFolder);
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
    beforeEach(() => {
      mockParseIpnsRecord.mockReset();
    });

    it('should resolve IPNS name to CID successfully', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: 5n,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi');
      expect(result!.sequenceNumber).toBe('5');
      expect(mockDelegatedRoutingClient.resolve).toHaveBeenCalledWith(testIpnsName);
    });

    it('should include base64-encoded signature fields when parser returns them', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
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
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
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
      // DelegatedRoutingClient.resolve() returns null for 404
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);

      const result = await service.resolveRecord(testIpnsName);

      expect(result).toBeNull();
      expect(mockDelegatedRoutingClient.resolve).toHaveBeenCalledTimes(1);
    });

    it('should return null for non-retryable HTTP errors (500) with no DB cache', async () => {
      // DelegatedRoutingClient throws BAD_GATEWAY on server errors
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should return null for BAD_GATEWAY errors with no DB cache', async () => {
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should parse CID from record with Qm prefix (CIDv0)', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
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
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
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
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: 'invalid-record-without-cid',
        sequence: 1n,
      });

      // The parsing throws BAD_GATEWAY, which falls through to DB cache -> null
      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should extract sequence number from IPNS record', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
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
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
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
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockImplementation(() => {
        throw new Error('Invalid protobuf');
      });

      // Parse error -> BAD_GATEWAY -> falls through to DB cache -> null
      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should fall back to DB-cached CID when delegated routing returns BAD_GATEWAY', async () => {
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
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

    it('should fall back to DB-cached CID after delegated routing network errors', async () => {
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve after retries', HttpStatus.BAD_GATEWAY)
      );
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
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should return null when routing fails and DB cache has no CID', async () => {
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: null,
      });

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should fall back to DB on parse errors (BAD_GATEWAY)', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockImplementation(() => {
        throw new Error('Invalid protobuf');
      });
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED_PARSE',
        sequenceNumber: '7',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      // Parse error -> BAD_GATEWAY -> falls through to DB cache
      const result = await service.resolveRecord(testIpnsName);
      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyCACHED_PARSE');
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalled();
    });

    it('should prefer DB cache when it has a higher sequence number than network', async () => {
      // Network returns stale record (seq 3)
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafySTALE',
        sequence: 3n,
      });

      // DB has newer record (seq 10)
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyFRESH',
        sequenceNumber: '10',
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyFRESH');
      expect(result!.sequenceNumber).toBe('10');
    });

    it('should prefer network result when it has equal or higher sequence than DB', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafyNETWORK',
        sequence: 10n,
      });

      // DB has same sequence
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyDB',
        sequenceNumber: '10',
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyNETWORK');
      expect(result!.sequenceNumber).toBe('10');
    });

    describe('resolve latency metrics', () => {
      it('should observe ipnsResolveDuration with source=network on successful network resolution', async () => {
        const mockRecordBytes = new Uint8Array([1, 2, 3]);
        mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
        mockParseIpnsRecord.mockReturnValue({
          value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
          sequence: 5n,
        });
        mockFolderIpnsRepo.findOne.mockResolvedValue(null);

        await service.resolveRecord(testIpnsName);

        expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
          { source: 'network', outcome: 'success' },
          expect.any(Number)
        );
      });

      it('should observe ipnsResolveDuration with source=db_cache on DB fallback', async () => {
        mockDelegatedRoutingClient.resolve.mockRejectedValue(
          new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
        );
        mockFolderIpnsRepo.findOne.mockResolvedValue({
          ...mockFolderEntity,
          latestCid: 'bafyCACHED',
          sequenceNumber: '42',
        });

        await service.resolveRecord(testIpnsName);

        expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
          { source: 'db_cache', outcome: 'error' },
          expect.any(Number)
        );
      });

      it('should observe ipnsResolveDuration with source=network_stale when DB has newer sequence', async () => {
        const mockRecordBytes = new Uint8Array([1, 2, 3]);
        mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
        mockParseIpnsRecord.mockReturnValue({
          value: '/ipfs/bafySTALE',
          sequence: 3n,
        });
        mockFolderIpnsRepo.findOne.mockResolvedValue({
          ...mockFolderEntity,
          latestCid: 'bafyFRESH',
          sequenceNumber: '10',
        });

        await service.resolveRecord(testIpnsName);

        expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
          { source: 'network_stale', outcome: 'success' },
          expect.any(Number)
        );
      });

      it('should NOT observe ipnsResolveDuration when result is null (not found)', async () => {
        mockDelegatedRoutingClient.resolve.mockResolvedValue(null);
        mockFolderIpnsRepo.findOne.mockResolvedValue(null);

        const result = await service.resolveRecord(testIpnsName);

        expect(result).toBeNull();
        expect(mockMetricsService.ipnsResolveDuration.observe).not.toHaveBeenCalled();
      });

      it('should observe ipnsResolveDuration with source=db_cache when network returns null but DB has data', async () => {
        mockDelegatedRoutingClient.resolve.mockResolvedValue(null);
        mockFolderIpnsRepo.findOne.mockResolvedValue({
          ...mockFolderEntity,
          latestCid: 'bafyCACHED_NULL_NET',
          sequenceNumber: '7',
        });

        await service.resolveRecord(testIpnsName);

        expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
          { source: 'db_cache', outcome: 'success' },
          expect.any(Number)
        );
      });
    });
  });

  describe('delegated routing failures are non-fatal', () => {
    beforeEach(() => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);
    });

    it('should succeed when delegated routing rejects with string error', async () => {
      mockDelegatedRoutingClient.publish.mockRejectedValue('string error');

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });
      expect(result.success).toBe(true);
      expect(mockFolderIpnsRepo.save).toHaveBeenCalled();
    });

    it('should succeed when delegated routing returns BAD_GATEWAY', async () => {
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });
      expect(result.success).toBe(true);
      expect(mockFolderIpnsRepo.save).toHaveBeenCalled();
    });

    it('should succeed when delegated routing throws network error', async () => {
      mockDelegatedRoutingClient.publish.mockRejectedValue(new Error('ECONNREFUSED'));

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });
      expect(result.success).toBe(true);
      expect(mockFolderIpnsRepo.save).toHaveBeenCalled();
    });
  });

  describe('duration instrumentation', () => {
    it('should observe resolve duration with correct labels on network success', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        sequence: 5n,
      });

      await service.resolveRecord(testIpnsName);

      expect(mockStartTimer).toHaveBeenCalledWith({ operation: 'resolve' });
      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'success', source: 'network' });
      expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
        { source: 'network', outcome: 'success' },
        expect.any(Number)
      );
    });

    it('should observe resolve duration with db source when DB has higher seq', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafySTALE',
        sequence: 3n,
      });
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyFRESH',
        sequenceNumber: '10',
      });

      await service.resolveRecord(testIpnsName);

      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'success', source: 'db' });
      expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
        { source: 'network_stale', outcome: 'success' },
        expect.any(Number)
      );
    });

    it('should observe resolve duration with error label on delegated routing failure', async () => {
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED',
        sequenceNumber: '42',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      await service.resolveRecord(testIpnsName);

      expect(mockStartTimer).toHaveBeenCalledWith({ operation: 'resolve' });
      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'error', source: 'db' });
      expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
        { source: 'db_cache', outcome: 'error' },
        expect.any(Number)
      );
    });

    it('should not observe ipnsResolveDuration when result is null (not found)', async () => {
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const result = await service.resolveRecord(testIpnsName);

      expect(result).toBeNull();
      expect(mockMetricsService.ipnsResolveDuration.observe).not.toHaveBeenCalled();
    });

    it('should observe publish duration on success', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      expect(mockStartTimer).toHaveBeenCalledWith({ operation: 'publish', source: '' });
      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'success' });
      expect(mockMetricsService.ipnsPublishDuration.observe).toHaveBeenCalledWith(
        { outcome: 'success' },
        expect.any(Number)
      );
    });

    it('should not observe ipnsPublishDuration when DB write fails before delegated publish', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockRejectedValue(new Error('DB write error'));

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).rejects.toThrow('DB write error');

      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'error' });
      expect(mockMetricsService.ipnsPublishDuration.observe).not.toHaveBeenCalled();
    });

    it('should observe ipnsPublishDuration with outcome=error on BAD_GATEWAY', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      expect(mockMetricsService.ipnsPublishDuration.observe).toHaveBeenCalledWith(
        { outcome: 'error' },
        expect.any(Number)
      );
    });

    it('should observe ipnsPublishDuration with outcome=error on HttpException BAD_GATEWAY (timeout)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);
      // DelegatedRoutingClient wraps timeouts/network errors into HttpException(BAD_GATEWAY)
      // after exhausting retries — AbortError never surfaces to IpnsService
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      expect(mockMetricsService.ipnsPublishDuration.observe).toHaveBeenCalledWith(
        { outcome: 'error' },
        expect.any(Number)
      );
    });
  });

  describe('conflict detection', () => {
    const createDto = (overrides?: Partial<PublishIpnsDto>): PublishIpnsDto => ({
      ipnsName: testIpnsName,
      record: testRecord,
      metadataCid: testMetadataCid,
      encryptedIpnsPrivateKey: testEncryptedIpnsPrivateKey,
      keyEpoch: testKeyEpoch,
      ...overrides,
    });

    it('rejects publish with stale expectedSequenceNumber (409)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '5' });

      const dto = createDto({ expectedSequenceNumber: '3' });

      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(ConflictException);

      try {
        await service.publishRecord(testUserId, dto);
      } catch (err) {
        expect(err).toBeInstanceOf(ConflictException);
        const response = (err as ConflictException).getResponse() as Record<string, unknown>;
        expect(response.currentSequenceNumber).toBe('5');
        expect(response.expectedSequenceNumber).toBe('3');
        expect(response.statusCode).toBe(409);
      }
    });

    it('accepts publish with matching expectedSequenceNumber', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '5' });
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve({ ...entity }));

      const dto = createDto({ expectedSequenceNumber: '5' });
      const result = await service.publishRecord(testUserId, dto);

      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe('6');
    });

    it('accepts publish without expectedSequenceNumber (backward compat)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '5' });
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve({ ...entity }));

      const dto = createDto(); // No expectedSequenceNumber
      const result = await service.publishRecord(testUserId, dto);

      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe('6');
    });

    it('rejects entire batch when folder record has stale sequence', async () => {
      // DB has sequenceNumber '5' for the folder
      mockFolderIpnsRepo.findOne.mockImplementation(
        async ({ where }: { where: { ipnsName: string } }) => {
          if (where.ipnsName === testIpnsName) {
            return { ...mockFolderEntity, sequenceNumber: '5' };
          }
          // File records: no existing entry
          return null;
        }
      );
      mockFolderIpnsRepo.create.mockImplementation((data) => ({ ...data, id: 'new-id' }));
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve({ ...entity }));

      const batchDto: BatchPublishIpnsDto = {
        records: [
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00001',
            record: testRecord,
            metadataCid: 'bafkreifile1',
            recordType: 'file',
          },
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00002',
            record: testRecord,
            metadataCid: 'bafkreifile2',
            recordType: 'file',
          },
          {
            ipnsName: testIpnsName,
            record: testRecord,
            metadataCid: testMetadataCid,
            recordType: 'folder',
            expectedSequenceNumber: '3', // Stale: DB has '5'
          },
        ],
      };

      await expect(service.publishBatch(testUserId, batchDto)).rejects.toThrow(ConflictException);
    });

    it('batch succeeds when folder record has matching sequence', async () => {
      mockFolderIpnsRepo.findOne.mockImplementation(
        async ({ where }: { where: { ipnsName: string } }) => {
          if (where.ipnsName === testIpnsName) {
            return { ...mockFolderEntity, sequenceNumber: '5' };
          }
          return null;
        }
      );
      mockFolderIpnsRepo.create.mockImplementation((data) => ({
        ...data,
        id: 'new-id',
        sequenceNumber: '1',
      }));
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve({ ...entity }));

      const batchDto: BatchPublishIpnsDto = {
        records: [
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00001',
            record: testRecord,
            metadataCid: 'bafkreifile1',
            recordType: 'file',
          },
          {
            ipnsName: testIpnsName,
            record: testRecord,
            metadataCid: testMetadataCid,
            recordType: 'folder',
            expectedSequenceNumber: '5', // Matches DB
          },
        ],
      };

      const result = await service.publishBatch(testUserId, batchDto);

      expect(result.totalSucceeded).toBe(2);
      expect(result.totalFailed).toBe(0);
      expect(result.results).toHaveLength(2);
      expect(result.results.every((r) => r.success)).toBe(true);
    });
  });
});
