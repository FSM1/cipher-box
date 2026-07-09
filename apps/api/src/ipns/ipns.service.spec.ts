import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import {
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { IpnsService } from './ipns.service';
import { IpnsRecord } from './entities/ipns-record.entity';
import { PublishIpnsDto, BatchPublishIpnsDto } from './dto';
import { User } from '../auth/entities/user.entity';
import { RepublishService } from '../republish/republish.service';
import { DelegatedRoutingClient } from './delegated-routing.client';
import { MetricsService } from '../metrics/metrics.service';
import { parseIpnsRecord, verifyIpnsRecordSignature } from '@cipherbox/crypto';
import { ipnsVerifyCache } from './ipns-verify-cache';

// Mock only the record parse + signature verification; keep deriveIpnsName real
// (the test IPNS name is derived from testPublicKeyBytes via the real function).
jest.mock('@cipherbox/crypto', () => {
  const actual = jest.requireActual('@cipherbox/crypto');
  return {
    ...actual,
    parseIpnsRecord: jest.fn(),
    verifyIpnsRecordSignature: jest.fn().mockResolvedValue(true),
  };
});
const mockParseIpnsRecord = parseIpnsRecord as jest.Mock;
const mockVerifyIpnsRecordSignature = verifyIpnsRecordSignature as jest.Mock;

describe('IpnsService', () => {
  let service: IpnsService;
  let mockFolderIpnsRepo: {
    findOne: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    createQueryBuilder: jest.Mock;
  };
  let mockQbExecute: jest.Mock;
  let mockQbSet: jest.Mock;
  let mockQbWhere: jest.Mock;
  let mockQbUpdate: jest.Mock;
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
  // Derived from testPublicKeyBytes via deriveIpnsName (must match for server-side validation)
  const testIpnsName = 'k51qzi5uqu5dg7hrs1jyr49oygapxsw71v7pv43rk8lemejo9h2m3hkzvww8io';
  const testMetadataCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
  const testRecord = btoa('test-ipns-record-bytes'); // base64 encoded
  const testRecordBytes = Buffer.from('test-ipns-record-bytes');
  const testPublicKeyBytes = Buffer.from(new Uint8Array(32).map((_, index) => index + 1));
  const testPublicKey = testPublicKeyBytes.toString('base64');
  const testEncryptedIpnsPrivateKey = 'a'.repeat(128); // 64 bytes hex
  const testKeyEpoch = 1;

  const mockFolderEntity: IpnsRecord = {
    id: 'folder-id-1',
    userId: testUserId,
    ipnsName: testIpnsName,
    latestCid: testMetadataCid,
    sequenceNumber: '5',
    signedRecord: null,
    encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
    keyEpoch: testKeyEpoch,
    isRoot: false,
    tombstonedAt: null,
    generation: '0',
    createdAt: new Date('2026-01-20T12:00:00.000Z'),
    updatedAt: new Date('2026-01-20T12:00:00.000Z'),
    user: {} as User,
  };

  beforeEach(async () => {
    mockQbExecute = jest.fn().mockResolvedValue({ affected: 1 });
    mockQbWhere = jest.fn().mockReturnThis();
    mockQbSet = jest.fn().mockReturnThis();
    mockQbUpdate = jest.fn().mockReturnThis();
    const mockQueryBuilder = {
      update: mockQbUpdate,
      set: mockQbSet,
      where: mockQbWhere,
      execute: mockQbExecute,
    };
    mockFolderIpnsRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      createQueryBuilder: jest.fn().mockReturnValue(mockQueryBuilder),
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
          provide: getRepositoryToken(IpnsRecord),
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
            unenrollIpns: jest.fn().mockResolvedValue(1),
          },
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
      ],
    }).compile();

    service = module.get<IpnsService>(IpnsService);

    // Defaults: records verify, and parse yields sequence 1n (D-03: first-publish requires 1).
    // Tests exercising existing-row paths override this with higher sequences as needed.
    mockVerifyIpnsRecordSignature.mockResolvedValue(true);
    mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 1n });
  });

  afterEach(() => {
    jest.clearAllMocks();
    // Clear the module-level verify cache so cross-test cache hits don't produce
    // false negatives on mockVerifyIpnsRecordSignature call-count assertions.
    ipnsVerifyCache.clear();
  });

  describe('publishRecord', () => {
    const createDto = (overrides?: Partial<PublishIpnsDto>): PublishIpnsDto => ({
      ipnsName: testIpnsName,
      record: testRecord,
      publicKey: testPublicKey,
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
      expect(mockFolderIpnsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          signedRecord: testRecordBytes,
        })
      );
    });

    it('should publish record for existing folder and increment sequence', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const result = await service.publishRecord(
        testUserId,
        createDto({ encryptedIpnsPrivateKey: undefined, keyEpoch: undefined })
      );

      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe('6');
      expect(mockQbExecute).toHaveBeenCalled();
      expect(mockQbSet).toHaveBeenCalledWith(
        expect.objectContaining({
          latestCid: testMetadataCid,
          signedRecord: testRecordBytes,
        })
      );
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

    it('should throw BadRequestException for invalid publicKey size', async () => {
      const invalidDto = createDto({ publicKey: Buffer.from([1, 2, 3]).toString('base64') });

      await expect(service.publishRecord(testUserId, invalidDto)).rejects.toThrow(
        'publicKey must be a raw 32-byte Ed25519 public key'
      );
    });

    it('should throw BadRequestException when publicKey does not derive to ipnsName', async () => {
      // Use a valid 32-byte key that does NOT derive to testIpnsName
      const wrongPublicKey = Buffer.from(new Uint8Array(32).fill(0xff)).toString('base64');
      const invalidDto = createDto({ publicKey: wrongPublicKey });

      await expect(service.publishRecord(testUserId, invalidDto)).rejects.toThrow(
        'publicKey does not correspond to the given ipnsName'
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
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const result = await service.publishRecord(testUserId, createDto());
      expect(result.success).toBe(true);
      expect(mockQbExecute).toHaveBeenCalled();
    });

    it('should succeed and save to DB even when delegated routing throws network error', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      mockDelegatedRoutingClient.publish.mockRejectedValue(new Error('Network error'));
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const result = await service.publishRecord(testUserId, createDto());
      expect(result.success).toBe(true);
      expect(mockQbExecute).toHaveBeenCalled();
    });

    it('should update encrypted key on key rotation for existing folder', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity });
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const newKeyEpoch = 2;
      const newEncryptedKey = 'b'.repeat(128);

      await service.publishRecord(
        testUserId,
        createDto({
          encryptedIpnsPrivateKey: newEncryptedKey,
          keyEpoch: newKeyEpoch,
        })
      );

      expect(mockQbSet).toHaveBeenCalledWith(
        expect.objectContaining({
          keyEpoch: newKeyEpoch,
          encryptedIpnsPrivateKey: Buffer.from(newEncryptedKey, 'hex'),
        })
      );
    });

    it('should not update encrypted key if only keyEpoch is provided', async () => {
      const originalEntity = { ...mockFolderEntity };
      mockFolderIpnsRepo.findOne.mockResolvedValue(originalEntity);
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      await service.publishRecord(
        testUserId,
        createDto({
          encryptedIpnsPrivateKey: undefined,
          keyEpoch: 2,
        })
      );

      // shouldUpdateKey=false when encryptedIpnsPrivateKey is absent — neither field
      // appears in the atomic CAS setClause; the DB row's original values are preserved.
      const setArgs = mockQbSet.mock.calls[0][0];
      expect(setArgs).not.toHaveProperty('keyEpoch');
      expect(setArgs).not.toHaveProperty('encryptedIpnsPrivateKey');
    });
  });

  describe('getIpnsRecord', () => {
    it('should return folder entry when found', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);

      const result = await service.getIpnsRecord(testUserId, testIpnsName);

      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalledWith({
        where: { userId: testUserId, ipnsName: testIpnsName },
      });
      expect(result).toEqual(mockFolderEntity);
    });

    it('should return null when folder not found', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const result = await service.getIpnsRecord(testUserId, testIpnsName);

      expect(result).toBeNull();
    });
  });

  describe('getAllIpnsRecords', () => {
    it('should return all folder entries for user', async () => {
      const folders = [
        mockFolderEntity,
        { ...mockFolderEntity, id: 'folder-id-2', ipnsName: 'k51another' },
      ];
      mockFolderIpnsRepo.find.mockResolvedValue(folders);

      const result = await service.getAllIpnsRecords(testUserId);

      expect(mockFolderIpnsRepo.find).toHaveBeenCalledWith({
        where: { userId: testUserId },
        order: { createdAt: 'ASC' },
      });
      expect(result).toEqual(folders);
      expect(result).toHaveLength(2);
    });

    it('should return empty array when user has no folders', async () => {
      mockFolderIpnsRepo.find.mockResolvedValue([]);

      const result = await service.getAllIpnsRecords(testUserId);

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

      expect(mockFolderIpnsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: testUserId,
          ipnsName: testIpnsName,
          latestCid: testMetadataCid,
          sequenceNumber: '1',
          signedRecord: testRecordBytes,
          encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
          keyEpoch: testKeyEpoch,
          isRoot: false,
        })
      );
    });

    it('should increment sequence number for existing folder', async () => {
      const existingFolder = { ...mockFolderEntity, sequenceNumber: '10' };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingFolder);
      // D-09: existing row at seq 10, forward publish requires embedded = 11n.
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 11n,
      });

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      expect(result.sequenceNumber).toBe('11');
      expect(mockQbSet).toHaveBeenCalledWith(
        expect.objectContaining({ latestCid: testMetadataCid })
      );
    });

    it('should handle BigInt sequence number correctly', async () => {
      const largeSeqFolder = {
        ...mockFolderEntity,
        sequenceNumber: '9007199254740991', // MAX_SAFE_INTEGER
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(largeSeqFolder);
      // D-09: existing row at MAX_SAFE_INTEGER, forward publish requires embedded = MAX_SAFE_INTEGER + 1.
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: BigInt('9007199254740992'), // MAX_SAFE_INTEGER + 1
      });

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      expect(result.sequenceNumber).toBe('9007199254740992'); // MAX_SAFE_INTEGER + 1
    });

    it('should update timestamp on existing folder update', async () => {
      const existingFolder = {
        ...mockFolderEntity,
        updatedAt: new Date('2020-01-01'),
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingFolder);
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const beforeTest = new Date();
      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });
      const afterTest = new Date();

      const setArgs = mockQbSet.mock.calls[0][0];
      expect(setArgs.updatedAt.getTime()).toBeGreaterThanOrEqual(beforeTest.getTime());
      expect(setArgs.updatedAt.getTime()).toBeLessThanOrEqual(afterTest.getTime());
    });

    // S1: embedded-vs-DTO CID validation (D-01)
    it('should throw BadRequestException (400) when embedded CID does not match metadataCid', async () => {
      // No existing entry — first-publish path. mockFolderEntity has signedRecord: null so
      // the anti-rollback block does NOT run; S1 calls parseIpnsRecord once for the check.
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      const differentCid = 'bafkreidifferentcidthatdoesnotmatchthedto123456789abcdef';
      // Override the global default so the embedded CID differs from testMetadataCid
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${differentCid}`,
        sequence: 1n,
      });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          expectedSequenceNumber: '0',
        })
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    // S1: offset-aware sequence mismatch on non-first-publish (D-01)
    it('should throw BadRequestException (400) when embedded sequence mismatches expectedSequenceNumber on update', async () => {
      // Existing entry with signedRecord so anti-rollback parses incoming+stored.
      // mockFolderEntity.sequenceNumber = '5', expectedSequenceNumber = '5'.
      // Non-first publish convention: embedded must be expectedSeq + 1n = 6n.
      // We submit embedded sequence 7n → mismatch → 400.
      const existingWithRecord = {
        ...mockFolderEntity,
        signedRecord: Buffer.from('stored-record-bytes'),
        sequenceNumber: '5',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingWithRecord);
      mockFolderIpnsRepo.save.mockResolvedValue({ ...existingWithRecord, sequenceNumber: '6' });
      // Promise.all: incoming parsed first, stored parsed second
      mockParseIpnsRecord
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 7n }) // incoming: seq 7 (should be 6)
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 5n }); // stored

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          expectedSequenceNumber: '5',
        })
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    // D-03: first publish with embedded seq 0n is now rejected (strict: only 1 allowed)
    it('should reject embedded sequence 0n on first publish (D-03: strict, pre-increment no longer tolerated)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      // embedded seq 0n → D-03 gate fires → BadRequestException
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 0n,
      });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          expectedSequenceNumber: '0',
        })
      ).rejects.toThrow(BadRequestException);

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          expectedSequenceNumber: '0',
        })
      ).rejects.toThrow(/embedded sequence must be 1, got 0/);
    });

    // S1: first-publish tolerance — embedded seq 1n also accepted
    it('should accept embedded sequence 1n on first publish (pre-increment convention)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });
      // embedded seq 1n with expectedSequenceNumber '0' → diff is 1n → accepted
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 1n,
      });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          expectedSequenceNumber: '0',
        })
      ).resolves.toBeDefined();
    });

    // S1: valid pass-through — embedded CID matches and seq is expectedSeq+1 (non-first)
    it('should pass through when embedded CID and sequence both match DTO on update', async () => {
      const existingWithRecord = {
        ...mockFolderEntity,
        signedRecord: Buffer.from('stored-record-bytes'),
        sequenceNumber: '5',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingWithRecord);
      // CID matches; embedded seq = expectedSeq + 1n = 6n → passes S1
      mockParseIpnsRecord
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 6n }) // incoming
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 5n }); // stored

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
        expectedSequenceNumber: '5',
      });

      expect(result.success).toBe(true);
      expect(mockQbExecute).toHaveBeenCalled();
    });

    // S1 regression guard: the anti-rollback 409 must still fire (not replaced by S1)
    it('should throw ConflictException (409) for anti-rollback sequence regression (regression guard)', async () => {
      const stored = {
        ...mockFolderEntity,
        signedRecord: Buffer.from('stored-record-bytes'),
        sequenceNumber: '9',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(stored);
      // incoming.sequence (3n) < stored.sequence (9n) → anti-rollback fires before S1
      mockParseIpnsRecord
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 3n }) // incoming
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 9n }); // stored

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).rejects.toBeInstanceOf(ConflictException);
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
      const sigBytes = new Uint8Array(64).fill(0xab);
      const dataBytes = new Uint8Array(48).fill(0xcd);
      const pubKeyBytes = new Uint8Array(32).fill(0xef);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafyCACHED',
        sequence: 42n,
        signatureV2: sigBytes,
        data: dataBytes,
        pubKey: pubKeyBytes,
      });
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED',
        sequenceNumber: '42',
        signedRecord: Buffer.from([9, 9, 9]),
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyCACHED');
      expect(result!.sequenceNumber).toBe('42');
      expect(result!.signatureV2).toBe(Buffer.from(sigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(dataBytes).toString('base64'));
      expect(result!.pubKey).toBe(Buffer.from(pubKeyBytes).toString('base64'));
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalledWith({
        where: { ipnsName: testIpnsName },
      });
    });

    it('should fall back to DB-cached CID after delegated routing network errors', async () => {
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve after retries', HttpStatus.BAD_GATEWAY)
      );
      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED2',
        sequenceNumber: '10',
        signedRecord: signedRecordBytes,
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);
      // parseCachedRecord will call parseIpnsRecordBytes on the signedRecord
      mockParseIpnsRecord.mockReturnValueOnce({
        value: '/ipfs/bafyCACHED2',
        sequence: 10n,
      });

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

    it('should return null when network parse errors and DB row has null signedRecord', async () => {
      // D-06: parseCachedRecord returns null for null-signedRecord rows.
      // Network parse throws BAD_GATEWAY; DB row has no signedRecord → both sources null → 404.
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockImplementation(() => {
        throw new Error('Invalid protobuf');
      });
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED_PARSE',
        sequenceNumber: '7',
        signedRecord: null,
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      // Network parse throws BAD_GATEWAY; DB has null signedRecord → null → 404
      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalled();
    });

    it('should fall back to DB on network errors when DB row has valid signedRecord', async () => {
      // D-06 success path: delegated routing throws BAD_GATEWAY; DB row has signedRecord.
      // parseCachedRecord succeeds → non-null result returned.
      // NOTE: test CIDs must use only [a-zA-Z0-9] chars (no underscores) to pass
      // the CID extraction regex in parseIpnsRecordBytes.
      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      const sigBytes = new Uint8Array(64).fill(0xcc);
      const dataBytes = new Uint8Array(48).fill(0xdd);
      const testCid = 'bafyCAcHeDPaRsE7777777777777777777777777777777777777777777777777';
      // Simulate delegated routing network failure (BAD_GATEWAY thrown directly from client)
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
      // DB signedRecord parse via parseCachedRecord — first (and only) parseIpnsRecord call
      mockParseIpnsRecord.mockResolvedValueOnce({
        value: `/ipfs/${testCid}`,
        sequence: 7n,
        signatureV2: sigBytes,
        data: dataBytes,
        pubKey: testPublicKeyBytes,
      });
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: testCid,
        sequenceNumber: '7',
        signedRecord: signedRecordBytes,
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);

      const result = await service.resolveRecord(testIpnsName);
      expect(result).not.toBeNull();
      expect(result!.cid).toBe(testCid);
      expect(result!.sequenceNumber).toBe('7');
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalled();
    });

    it('should prefer DB cache when it has a higher sequence number than network', async () => {
      // Network returns stale record (seq 3)
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord
        .mockReturnValueOnce({
          value: '/ipfs/bafySTALE',
          sequence: 3n,
        })
        .mockReturnValueOnce({
          value: '/ipfs/bafyFRESH',
          sequence: 10n,
          signatureV2: new Uint8Array(64).fill(1),
          data: new Uint8Array(48).fill(2),
          pubKey: new Uint8Array(32).fill(3),
        });

      // DB has newer record (seq 10)
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyFRESH',
        sequenceNumber: '10',
        signedRecord: Buffer.from([4, 5, 6]),
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyFRESH');
      expect(result!.sequenceNumber).toBe('10');
      expect(result!.signatureV2).toBeDefined();
    });

    it('should derive pubKey from the IPNS name when the DB publicKey column is null', async () => {
      // Regression (web-e2e writable-shares 3.4): Phase 60 D-06 discarded an authoritative
      // DB record whose nullable publicKey column was never populated — true for
      // writable-shared-folder rows — so strict resolve returned nothing and read-after-edit
      // broke. The Ed25519 name encodes the public key, so it must be recovered from the name.
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      const sigBytes = new Uint8Array(64).fill(0x11);
      const dataBytes = new Uint8Array(48).fill(0x22);
      mockParseIpnsRecord
        // network parse: stale (seq 3)
        .mockReturnValueOnce({ value: '/ipfs/bafySTALE', sequence: 3n })
        // cached parse: fresher (seq 10); an Ed25519 record carries NO embedded pubKey
        .mockReturnValueOnce({
          value: '/ipfs/bafyFRESH',
          sequence: 10n,
          signatureV2: sigBytes,
          data: dataBytes,
          // pubKey intentionally absent
        });

      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyFRESH',
        sequenceNumber: '10',
        signedRecord: Buffer.from([4, 5, 6]),
        publicKey: null, // shared-folder row: column never populated
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyFRESH');
      // testIpnsName derives from testPublicKeyBytes ([1..32]); recovered pubKey must match.
      expect(result!.pubKey).toBe(testPublicKey);
      expect(result!.signatureV2).toBe(Buffer.from(sigBytes).toString('base64'));
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

    it('should supplement pubKey from the IPNS name for a signature-bearing network record when DB signedRecord is null', async () => {
      // Phase 66 (§6.5 seqFloor serve): Ed25519 identity records omit the embedded pubKey
      // (the name encodes the key), so a network-resolved record carries signatureV2/data but
      // no pubKey. resolveRecord supplements pubKey from the requested name (publicKeyFromIpnsName) —
      // the same trust model as the DB-cached path — so a shared-folder (null signedRecord) row
      // still yields a client-verifiable record instead of failing the strict client closed.
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      const sigBytes = new Uint8Array(64).fill(0x12);
      const dataBytes = new Uint8Array(48).fill(0x34);

      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafyNETWORK',
        sequence: 10n,
        signatureV2: sigBytes,
        data: dataBytes,
      });
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyDB',
        sequenceNumber: '10',
        signedRecord: null,
        publicKey: testPublicKeyBytes,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyNETWORK');
      // pubKey supplemented from the name (identity records omit it) so the all-or-nothing
      // signature bundle is complete and the strict client can verify.
      expect(result!.pubKey).toBe(Buffer.from(testPublicKeyBytes).toString('base64'));
      expect(result!.signatureV2).toBe(Buffer.from(sigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(dataBytes).toString('base64'));
    });

    // seqFloor gate (§6.5 / TEE-05) — unit coverage for the shared-folder
    // null-signedRecord rows previously exercised only by sdk-e2e Test 15.
    it('seqFloor gate: fails closed (null) when the network record is below the stored floor', async () => {
      // A shared-folder row has a null signedRecord and carries a sequence floor. A network
      // record strictly BELOW that floor must not be served — serving it would expose a
      // rolled-back CID for a shared name. Fail closed → null → 404.
      mockDelegatedRoutingClient.resolve.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafyNETWORK',
        sequence: 1n, // network seq = 1
        signatureV2: new Uint8Array(64).fill(0x12),
        data: new Uint8Array(48).fill(0x34),
      });
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyDB',
        sequenceNumber: '100', // floor = 100 > network seq = 1
        signedRecord: null,
      });

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('seqFloor gate: serves the network record when it is at/above the stored floor', async () => {
      // The at-floor counterpart to the below-floor case: network seq == floor → serve the
      // network record (pubKey supplemented from the name so the strict client can verify).
      mockDelegatedRoutingClient.resolve.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafyNETWORK',
        sequence: 5n, // network seq = 5
        signatureV2: new Uint8Array(64).fill(0x12),
        data: new Uint8Array(48).fill(0x34),
      });
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyDB',
        sequenceNumber: '5', // floor = 5 == network seq = 5 → at floor → serves
        signedRecord: null,
      });

      const result = await service.resolveRecord(testIpnsName);
      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyNETWORK');
      expect(result!.sequenceNumber).toBe('5');
    });

    it('fails closed (null) when the cached signedRecord is unparseable and there is no network record', async () => {
      // A row with garbage signed_record bytes and no network record must fail closed.
      // parseCachedRecord throws while parsing the bytes → returns null, so resolveRecord
      // returns null → 404 (no ungated fallthrough).
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);
      mockParseIpnsRecord.mockImplementation(() => {
        throw new Error('Invalid protobuf');
      });
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafySTUB',
        sequenceNumber: '1',
        signedRecord: Buffer.from([1, 2, 3, 4]), // unparseable
      });

      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should serve the authoritative DB record with full signature fields when sequences are equal (strict resolve verifiability)', async () => {
      // On equal sequence the DB-cached record is the authoritative, fully-signed record.
      // resolveRecord must serve it — with signatureV2/data from the signed bytes and pubKey
      // supplied from the validated publicKey column — so a strict client can verify. The
      // network record parsed from delegated routing lacks those fields. (Corrects Plan
      // 60-05's enrich removal, which returned the bare network result and broke the strict
      // publish→resolve round-trip; the client re-checks the pubKey→name binding.)
      const mockRecordBytes = new Uint8Array([1, 2, 3]);

      // Network returns record WITHOUT signature fields
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);

      // DB cache has same sequence WITH signedRecord containing signature data
      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      const sigBytes = new Uint8Array(64).fill(0xaa);
      const dataBytes = new Uint8Array(48).fill(0xbb);
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyNETWORK',
        sequenceNumber: '10',
        signedRecord: signedRecordBytes,
        publicKey: testPublicKeyBytes,
      });

      // First call: network parse (no sig fields); second call: DB signedRecord parse
      // (sig + data, but NO pubKey — realistic Ed25519).
      mockParseIpnsRecord
        .mockReturnValueOnce({
          value: '/ipfs/bafyNETWORK',
          sequence: 10n,
        })
        .mockReturnValueOnce({
          value: '/ipfs/bafyNETWORK',
          sequence: 10n,
          signatureV2: sigBytes,
          data: dataBytes,
        });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyNETWORK');
      expect(result!.sequenceNumber).toBe('10');
      // The authoritative DB record is served with complete, verifiable signature fields.
      expect(result!.signatureV2).toBe(Buffer.from(sigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(dataBytes).toString('base64'));
      expect(result!.pubKey).toBe(testPublicKey);
    });

    it('should return null when DB signedRecord CID mismatches latestCid (D-06: mismatch discarded)', async () => {
      // D-06: CID mismatch between signedRecord embedded CID and DB latestCid →
      // parseCachedRecord returns null (inconsistent row discarded, not overridden).
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);

      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      // DB latestCid='bafyNEWER' but signedRecord embeds 'bafyOLDER' — inconsistent
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyNEWER',
        sequenceNumber: '5',
        signedRecord: signedRecordBytes,
        publicKey: testPublicKeyBytes,
      });

      mockParseIpnsRecord.mockReturnValueOnce({
        value: '/ipfs/bafyOLDER',
        sequence: 0n,
        signatureV2: new Uint8Array(64).fill(0xcc),
        data: new Uint8Array(48).fill(0xdd),
      });

      // Mismatch → parseCachedRecord discards → null → 404
      const result = await service.resolveRecord(testIpnsName);
      expect(result).toBeNull();
    });

    it('should use DB sequenceNumber when signedRecord CID matches latestCid', async () => {
      // D-06 success path: CID matches → DB seq is authoritative, sig fields from record.
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);

      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      const cachedSigBytes = new Uint8Array(64).fill(0xcc);
      const cachedDataBytes = new Uint8Array(48).fill(0xdd);

      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyCONSISTENT',
        sequenceNumber: '5',
        signedRecord: signedRecordBytes,
        publicKey: testPublicKeyBytes,
      });

      // signedRecord embeds same CID as latestCid → consistent → parseCachedRecord succeeds
      mockParseIpnsRecord.mockReturnValueOnce({
        value: '/ipfs/bafyCONSISTENT',
        sequence: 4n, // stale seq in bytes — DB seq '5' is authoritative
        signatureV2: cachedSigBytes,
        data: cachedDataBytes,
        pubKey: testPublicKeyBytes,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      // DB sequenceNumber is authoritative
      expect(result!.cid).toBe('bafyCONSISTENT');
      expect(result!.sequenceNumber).toBe('5');
      // Signature fields from parsed signed record
      expect(result!.signatureV2).toBe(Buffer.from(cachedSigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(cachedDataBytes).toString('base64'));
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

      it('should observe ipnsResolveDuration with source=db_cache on DB fallback (with valid signedRecord)', async () => {
        // D-06: DB fallback only fires when signedRecord is present; null-signedRecord → null → no metrics.
        const signedRecordBytes = new Uint8Array([4, 5, 6]);
        mockDelegatedRoutingClient.resolve.mockRejectedValue(
          new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
        );
        mockFolderIpnsRepo.findOne.mockResolvedValue({
          ...mockFolderEntity,
          latestCid: 'bafyCACHED',
          sequenceNumber: '42',
          signedRecord: signedRecordBytes,
        });
        mockParseIpnsRecord.mockReturnValueOnce({
          value: '/ipfs/bafyCACHED',
          sequence: 42n,
        });

        await service.resolveRecord(testIpnsName);

        expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
          { source: 'db_cache', outcome: 'error' },
          expect.any(Number)
        );
      });

      it('should observe ipnsResolveDuration with source=network_stale when DB has newer sequence', async () => {
        // D-06: DB must have a valid signedRecord for parseCachedRecord to return non-null.
        const mockRecordBytes = new Uint8Array([1, 2, 3]);
        const signedRecordBytes = new Uint8Array([7, 8, 9]);
        mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
        mockFolderIpnsRepo.findOne.mockResolvedValue({
          ...mockFolderEntity,
          latestCid: 'bafyFRESH',
          sequenceNumber: '10',
          signedRecord: signedRecordBytes,
        });
        mockParseIpnsRecord
          .mockReturnValueOnce({
            // Network parse: stale record
            value: '/ipfs/bafySTALE',
            sequence: 3n,
          })
          .mockReturnValueOnce({
            // DB signedRecord parse via parseCachedRecord
            value: '/ipfs/bafyFRESH',
            sequence: 10n,
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

      it('should observe ipnsResolveDuration with source=db_cache when network returns null but DB has valid signedRecord', async () => {
        // D-06: DB must have a valid signedRecord for parseCachedRecord to return non-null.
        // NOTE: test CIDs must use only [a-zA-Z0-9] chars to pass CID regex extraction.
        const signedRecordBytes = new Uint8Array([4, 5, 6]);
        const testCid = 'bafyCAcHeDnULLNeT7777777777777777777777777777777777777777777777777';
        mockDelegatedRoutingClient.resolve.mockResolvedValue(null);
        mockFolderIpnsRepo.findOne.mockResolvedValue({
          ...mockFolderEntity,
          latestCid: testCid,
          sequenceNumber: '7',
          signedRecord: signedRecordBytes,
        });
        // Use mockResolvedValue (permanent) since this is the only parseIpnsRecord call
        mockParseIpnsRecord.mockResolvedValue({
          value: `/ipfs/${testCid}`,
          sequence: 7n,
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
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });
    });

    it('should succeed when delegated routing rejects with string error', async () => {
      mockDelegatedRoutingClient.publish.mockRejectedValue('string error');

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });
      expect(result.success).toBe(true);
      expect(mockQbExecute).toHaveBeenCalled();
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
      expect(mockQbExecute).toHaveBeenCalled();
    });

    it('should succeed when delegated routing throws network error', async () => {
      mockDelegatedRoutingClient.publish.mockRejectedValue(new Error('ECONNREFUSED'));

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });
      expect(result.success).toBe(true);
      expect(mockQbExecute).toHaveBeenCalled();
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

    it('should observe resolve duration with db source when DB has higher seq (valid signedRecord)', async () => {
      // D-06: DB must have a valid signedRecord for parseCachedRecord to return non-null.
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      const signedRecordBytes = new Uint8Array([7, 8, 9]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyFRESH',
        sequenceNumber: '10',
        signedRecord: signedRecordBytes,
      });
      mockParseIpnsRecord
        .mockReturnValueOnce({
          // Network parse: stale record
          value: '/ipfs/bafySTALE',
          sequence: 3n,
        })
        .mockReturnValueOnce({
          // DB signedRecord parse
          value: '/ipfs/bafyFRESH',
          sequence: 10n,
        });

      await service.resolveRecord(testIpnsName);

      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'success', source: 'db' });
      expect(mockMetricsService.ipnsResolveDuration.observe).toHaveBeenCalledWith(
        { source: 'network_stale', outcome: 'success' },
        expect.any(Number)
      );
    });

    it('should observe resolve duration with error label on delegated routing failure (valid signedRecord)', async () => {
      // D-06: DB must have a valid signedRecord for parseCachedRecord to return non-null.
      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      mockDelegatedRoutingClient.resolve.mockRejectedValue(
        new HttpException('Failed to resolve', HttpStatus.BAD_GATEWAY)
      );
      const cachedFolder = {
        ...mockFolderEntity,
        latestCid: 'bafyCACHED',
        sequenceNumber: '42',
        signedRecord: signedRecordBytes,
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(cachedFolder);
      mockParseIpnsRecord.mockReturnValueOnce({
        value: '/ipfs/bafyCACHED',
        sequence: 42n,
      });

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

      // Delegated routing publish is fire-and-forget; flush microtask queue
      // so the detached .then() callback that records metrics can run.
      await new Promise(process.nextTick);

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
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      // Delegated routing publish is fire-and-forget; flush microtask queue
      await new Promise(process.nextTick);

      expect(mockMetricsService.ipnsPublishDuration.observe).toHaveBeenCalledWith(
        { outcome: 'error' },
        expect.any(Number)
      );
    });

    it('should observe ipnsPublishDuration with outcome=error on HttpException BAD_GATEWAY (timeout)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(mockFolderEntity);
      // DelegatedRoutingClient wraps timeouts/network errors into HttpException(BAD_GATEWAY)
      // after exhausting retries — AbortError never surfaces to IpnsService
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      // Delegated routing publish is fire-and-forget; flush microtask queue
      await new Promise(process.nextTick);

      expect(mockMetricsService.ipnsPublishDuration.observe).toHaveBeenCalledWith(
        { outcome: 'error' },
        expect.any(Number)
      );
    });

    it('should log error and not crash when metrics observe() throws', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockMetricsService.ipnsPublishDuration.observe.mockImplementation(() => {
        throw new Error('metrics explosion');
      });

      const loggerSpy = jest.spyOn(service['logger'], 'error').mockImplementation();

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      // Flush fire-and-forget promise chain
      await new Promise(process.nextTick);

      expect(result.success).toBe(true);
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to record IPNS publish metrics')
      );

      loggerSpy.mockRestore();
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
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5' };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      // Forward publish passes D-09; atomic CAS WHERE clause fails (expected='3' != actual '5').
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });
      mockQbExecute.mockResolvedValue({ affected: 0 });

      const dto = createDto({ expectedSequenceNumber: '3' });

      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(ConflictException);

      try {
        await service.publishRecord(testUserId, dto);
      } catch (err) {
        expect(err).toBeInstanceOf(ConflictException);
        const response = (err as ConflictException).getResponse() as Record<string, unknown>;
        expect(response.currentSequenceNumber).toBe('5');
        expect(response.statusCode).toBe(409);
        // Note: expectedSequenceNumber is no longer surfaced in the 409 response body
      }
    });

    it('accepts publish with matching expectedSequenceNumber', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '5' });
      // S1 sequence check: expects embedded = expectedSeq + 1n = 6n
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const dto = createDto({ expectedSequenceNumber: '5' });
      const result = await service.publishRecord(testUserId, dto);

      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe('6');
    });

    it('accepts publish without expectedSequenceNumber (backward compat)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '5' });
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const dto = createDto(); // No expectedSequenceNumber
      const result = await service.publishRecord(testUserId, dto);

      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe('6');
    });

    it('rejects entire batch when folder record has stale sequence', async () => {
      // DB has sequenceNumber '5' for testIpnsName; no existing entry for other records.
      mockFolderIpnsRepo.findOne.mockImplementation(
        async ({ where }: { where: { ipnsName: string } }) => {
          if (where.ipnsName === testIpnsName) {
            return { ...mockFolderEntity, sequenceNumber: '5' };
          }
          return null;
        }
      );
      // Forward publish (6n) passes D-09 for the existing row; atomic CAS WHERE clause
      // fails (expected='3' != actual '5') → affected=0 → ConflictException rethrown by batch.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });
      mockQbExecute.mockResolvedValue({ affected: 0 });

      const batchDto: BatchPublishIpnsDto = {
        records: [
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00001',
            record: testRecord,
            metadataCid: testMetadataCid,
          },
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00002',
            record: testRecord,
            metadataCid: testMetadataCid,
          },
          {
            ipnsName: testIpnsName,
            record: testRecord,
            metadataCid: testMetadataCid,
            expectedSequenceNumber: '3', // Stale: DB has '5' → CAS affected=0 → 409
          },
        ],
      };

      await expect(service.publishBatch(testUserId, batchDto)).rejects.toThrow(ConflictException);
    });

    it('fails the entire batch with 410 GONE when a record is tombstoned (signal not masked)', async () => {
      // A tombstoned row: CAS WHERE (tombstoned_at IS NULL) never matches → affected=0 →
      // disambiguation read finds tombstonedAt set → publishRecord throws 410 GONE. The
      // batch must surface that, not mask it as { success: false, sequenceNumber: '0' }.
      mockFolderIpnsRepo.findOne.mockImplementation(
        async ({ where }: { where: { ipnsName: string } }) => {
          if (where.ipnsName === testIpnsName) {
            return { ...mockFolderEntity, sequenceNumber: '5', tombstonedAt: new Date() };
          }
          return null;
        }
      );
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });
      mockQbExecute.mockResolvedValue({ affected: 0 });

      const batchDto: BatchPublishIpnsDto = {
        records: [
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00001',
            record: testRecord,
            metadataCid: testMetadataCid,
          },
          {
            ipnsName: testIpnsName,
            record: testRecord,
            metadataCid: testMetadataCid,
            expectedSequenceNumber: '5',
          },
        ],
      };

      const err = await service.publishBatch(testUserId, batchDto).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(HttpException);
      expect((err as HttpException).getStatus()).toBe(HttpStatus.GONE);
      expect((err as HttpException).getResponse()).toMatchObject({ error: 'IPNS_TOMBSTONED' });
    });

    it('batch succeeds when folder record has matching sequence', async () => {
      // All records have an existing row at seq 5 so that a uniform embedded sequence
      // of 6n satisfies D-09's forward-publish rule for every entry.
      // This avoids an order-dependent mock (Promise.allSettled processes them concurrently).
      mockFolderIpnsRepo.findOne.mockImplementation(
        async ({ where }: { where: { ipnsName: string } }) => {
          if (where.ipnsName === testIpnsName) {
            return { ...mockFolderEntity, sequenceNumber: '5' };
          }
          // File records: existing entry at seq 5 (forward-publish with embedded=6n).
          return { ...mockFolderEntity, ipnsName: where.ipnsName, sequenceNumber: '5' };
        }
      );
      // D-09: all rows at seq 5; embedded=6n satisfies forward-publish for all entries.
      // Default mockQbExecute returns { affected: 1 } — all CAS updates succeed.
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 6n,
      });

      const batchDto: BatchPublishIpnsDto = {
        records: [
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00001',
            record: testRecord,
            metadataCid: testMetadataCid, // S1: matches embedded CID
          },
          {
            ipnsName: testIpnsName,
            record: testRecord,
            metadataCid: testMetadataCid,
            expectedSequenceNumber: '5', // Matches DB; embedded seq must be 6n
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

  // =========================================================================
  // Decentralized authority: signature-gated, ipnsName-keyed publishing
  // =========================================================================

  describe('publishRecord - signature-gated, ipnsName-keyed', () => {
    it('lets any holder of the key update the canonical record (non-owner publish)', async () => {
      const otherUser = '660e8400-e29b-41d4-a716-446655440001';
      // One canonical row per ipnsName, created by testUserId; looked up by name.
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity });
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const dto: PublishIpnsDto = {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      };

      const result = await service.publishRecord(otherUser, dto);

      expect(result.sequenceNumber).toBe('6');
      // Authorized by signature (verify mocked true); looked up by name alone —
      // no per-user / share authorization.
      expect(mockVerifyIpnsRecordSignature).toHaveBeenCalled();
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalledWith({
        where: { ipnsName: testIpnsName },
      });
      // The atomic UPDATE setClause does not include userId — the DB row's creator is preserved.
      const setArgs = mockQbSet.mock.calls[0][0];
      expect(setArgs).not.toHaveProperty('userId');
    });

    it('rejects a record whose signature does not verify', async () => {
      mockVerifyIpnsRecordSignature.mockResolvedValueOnce(false);

      const dto: PublishIpnsDto = {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      };

      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(BadRequestException);
      expect(mockFolderIpnsRepo.save).not.toHaveBeenCalled();
    });

    it('does not touch TEE enrollment when the publisher is not the row creator', async () => {
      const otherUser = '660e8400-e29b-41d4-a716-446655440001';
      mockFolderIpnsRepo.findOne.mockResolvedValue({ ...mockFolderEntity });
      // D-09: existing row at seq 5, forward publish requires embedded = 6n.
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

      const dto: PublishIpnsDto = {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
        encryptedIpnsPrivateKey: 'bb'.repeat(64),
        keyEpoch: 2,
      };

      await service.publishRecord(otherUser, dto);

      // shouldUpdateKey=false (publisher != row owner) → encryption fields absent from setClause.
      const setArgs = mockQbSet.mock.calls[0][0];
      expect(setArgs).not.toHaveProperty('encryptedIpnsPrivateKey');
      expect(setArgs).not.toHaveProperty('keyEpoch');
    });

    it('creates a new canonical entry for a first-time publisher', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      const newEntity = { ...mockFolderEntity, userId: 'new-user-id', sequenceNumber: '1' };
      mockFolderIpnsRepo.create.mockReturnValue(newEntity);
      mockFolderIpnsRepo.save.mockResolvedValue(newEntity);

      const dto: PublishIpnsDto = {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      };

      const result = await service.publishRecord('new-user-id', dto);
      expect(result.sequenceNumber).toBe('1');
    });

    it('rejects a replayed record whose embedded sequence regresses (anti-rollback)', async () => {
      const stored = {
        ...mockFolderEntity,
        signedRecord: Buffer.from('stored-record-bytes'),
        sequenceNumber: '9',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(stored);
      // Promise.all order: incoming record first, stored record second.
      mockParseIpnsRecord
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 4n }) // incoming
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 9n }); // stored

      const dto: PublishIpnsDto = {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      };

      await expect(service.publishRecord(testUserId, dto)).rejects.toThrow(ConflictException);
      expect(mockFolderIpnsRepo.save).not.toHaveBeenCalled();
    });

    it('accepts a record whose embedded sequence advances past the stored record', async () => {
      const stored = {
        ...mockFolderEntity,
        signedRecord: Buffer.from('stored-record-bytes'),
        sequenceNumber: '9',
      };
      mockFolderIpnsRepo.findOne.mockResolvedValue(stored);
      mockParseIpnsRecord
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 10n }) // incoming
        .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 9n }); // stored

      const dto: PublishIpnsDto = {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      };

      const result = await service.publishRecord(testUserId, dto);
      expect(result.sequenceNumber).toBe('10');
    });
  });

  describe('unenrollBatch', () => {
    function getRepublishMock() {
      return (service as unknown as Record<string, unknown>).republishService as {
        unenrollIpns: jest.Mock;
      };
    }

    it('should unenroll all provided IPNS names', async () => {
      const republishService = getRepublishMock();
      republishService.unenrollIpns.mockResolvedValue(1);

      const result = await service.unenrollBatch('user-1', [
        'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
        'k51qzi5uqu5dg12345abcdefghij1234567890abcdefghij12345678',
      ]);

      expect(result.totalUnenrolled).toBe(2);
      expect(republishService.unenrollIpns).toHaveBeenCalledTimes(2);
    });

    it('should continue processing when individual unenroll fails', async () => {
      const republishService = getRepublishMock();
      republishService.unenrollIpns
        .mockResolvedValueOnce(1) // first succeeds
        .mockRejectedValueOnce(new Error('not found')) // second fails
        .mockResolvedValueOnce(1); // third succeeds

      const result = await service.unenrollBatch('user-1', ['name1', 'name2', 'name3']);

      expect(result.totalUnenrolled).toBe(2);
      expect(republishService.unenrollIpns).toHaveBeenCalledTimes(3);
    });

    it('should return zero when all unenrolls fail', async () => {
      const republishService = getRepublishMock();
      republishService.unenrollIpns.mockRejectedValue(new Error('db error'));

      const result = await service.unenrollBatch('user-1', ['name1', 'name2']);

      expect(result.totalUnenrolled).toBe(0);
    });

    it('should handle empty array', async () => {
      const result = await service.unenrollBatch('user-1', []);
      expect(result.totalUnenrolled).toBe(0);
    });
  });

  describe('tombstoneRecord', () => {
    function getRepublishMock() {
      return (service as unknown as Record<string, unknown>).republishService as {
        unenrollIpns: jest.Mock;
      };
    }
    const OWNER = 'user-uuid-1';
    const NAME = 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz';

    it('tombstones an owned active record and unenrolls it (no disambiguating lookup)', async () => {
      mockQbExecute.mockResolvedValue({ affected: 1 });

      await expect(service.tombstoneRecord(OWNER, NAME)).resolves.toBeUndefined();

      expect(mockFolderIpnsRepo.findOne).not.toHaveBeenCalled();
      expect(getRepublishMock().unenrollIpns).toHaveBeenCalledWith(OWNER, NAME);
    });

    it('is idempotent for an already-tombstoned owned record (no throw)', async () => {
      mockQbExecute.mockResolvedValue({ affected: 0 });
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ipnsName: NAME,
        userId: OWNER,
        tombstonedAt: new Date(),
      });

      await expect(service.tombstoneRecord(OWNER, NAME)).resolves.toBeUndefined();

      expect(getRepublishMock().unenrollIpns).toHaveBeenCalledWith(OWNER, NAME);
    });

    it('throws NotFoundException for a non-existent or unowned name (no false 200)', async () => {
      mockQbExecute.mockResolvedValue({ affected: 0 });
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      await expect(service.tombstoneRecord(OWNER, NAME)).rejects.toBeInstanceOf(NotFoundException);

      expect(getRepublishMock().unenrollIpns).not.toHaveBeenCalled();
    });

    it('scopes both the UPDATE and the disambiguation lookup to the caller (owner-only contract)', async () => {
      // A name owned by another user must never be tombstoned by this caller. The
      // UPDATE WHERE is user-scoped, so it matches 0 rows, and the disambiguation
      // findOne is likewise user-scoped, so it returns null → NotFound. Pin both so
      // a regression that drops userId from either the CAS WHERE or the lookup is
      // caught (without the scoping a foreign row would be tombstoned or surface a
      // false 200).
      mockQbExecute.mockResolvedValue({ affected: 0 });
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);

      await expect(service.tombstoneRecord(OWNER, NAME)).rejects.toBeInstanceOf(NotFoundException);

      // UPDATE is owner-scoped (user_id = :userId, bound to the caller's id).
      expect(mockQbWhere).toHaveBeenCalledWith(
        expect.stringContaining('user_id = :userId'),
        expect.objectContaining({ ipnsName: NAME, userId: OWNER })
      );
      // Disambiguation lookup is owner-scoped (never a bare ipnsName match).
      expect(mockFolderIpnsRepo.findOne).toHaveBeenCalledWith({
        where: { ipnsName: NAME, userId: OWNER },
      });
    });
  });

  // =========================================================================
  // D-09: unconditional embedded-sequence gate (Plan 58-02)
  // =========================================================================

  describe('upsertFolderIpns D-09 embedded-sequence gate', () => {
    // Helper: build a publishRecord call without CAS (no expectedSequenceNumber)
    const publishNoCas = (overrides?: Partial<{ metadataCid: string; record: string }>) =>
      service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: overrides?.record ?? testRecord,
        metadataCid: overrides?.metadataCid ?? testMetadataCid,
        // intentionally no expectedSequenceNumber
      });

    it('rejects first publish with embedded sequence > 1 (wedge-poison prevention)', async () => {
      // No existing row — first publish path.
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      // Embedded seq 2n: not in the first-publish allow set {0n, 1n}.
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 2n,
      });

      await expect(publishNoCas()).rejects.toThrow(BadRequestException);
      await expect(publishNoCas()).rejects.toThrow(/first publish.*embedded sequence/i);
    });

    it('rejects first publish with embedded sequence 0n (D-03: strict, only 1 allowed)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 0n,
      });

      await expect(publishNoCas()).rejects.toThrow(BadRequestException);
      await expect(publishNoCas()).rejects.toThrow(/embedded sequence must be 1, got 0/);
    });

    it('allows first publish with embedded sequence 1n', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 1n,
      });

      await expect(publishNoCas()).resolves.toBeDefined();
    });

    // D-05: same-seq republish with a DIFFERENT CID is equivocation and must be
    // rejected 400; same-seq republish with the SAME CID is the genuine TEE
    // idempotent re-sign path and must still succeed with no sequence bump.
    //
    // Structural guard (non-inferable, documented): the TEE lease-renewer
    // (republish.service.ts renewIpnsRecordEol) NEVER reaches this same-seq
    // branch — it performs a standalone UPDATE that re-signs the existing
    // CID/seq in place and never calls upsertIpnsRecord/publishRecord. Only a
    // fresh, externally-signed publishRecord call embedding the current DB
    // sequence can hit this branch, which is exactly the equivocation case
    // D-05 guards against.
    it('rejects same-seq republish with a DIFFERENT CID (D-05: equivocation)', async () => {
      // Existing row at seq 5 with latestCid = testMetadataCid.
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      const divergentCid = 'bafkreidivergentcid00000000000000000000000000000000000000000000';
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${divergentCid}`,
        sequence: 5n, // embedded = DB seq = 5n, but CID diverges from existing.latestCid
      });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: divergentCid,
        })
      ).rejects.toThrow(BadRequestException);

      // Must not have applied the atomic UPDATE — rejected before the CAS write.
      expect(mockQbExecute).not.toHaveBeenCalled();
    });

    // D-05 refinement (ROT-05 regression caught by sdk-e2e concurrent-add-during-rotation):
    // a same-seq / DIFFERENT-CID publish that carries expectedSequenceNumber === embeddedSeq - 1
    // is a FORWARD-publish CAS attempt that LOST a concurrent race (a concurrent writer advanced
    // the row to embeddedSeq first), NOT equivocation. It must fall THROUGH to the atomic CAS
    // UPDATE and surface a 409 (which the client's publishWithCas merges), never a 400. The
    // equivocation protection is preserved: the CAS WHERE (expected != actual) still rejects the
    // write (affected=0), so no same-seq CID overwrite ever lands.
    it('treats same-seq/different-CID with a forward CAS expectation as a 409 race, not a 400 equivocation', async () => {
      // Existing row at seq 5. A concurrent writer already advanced it to 5 with its own CID;
      // this publish embeds seq 5 with a DIFFERENT CID but expected '4' (its pre-race view).
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      const divergentCid = 'bafkreidivergentcid00000000000000000000000000000000000000000000';
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${divergentCid}`,
        sequence: 5n, // embedded === DB seq === 5n
      });
      // CAS fails: WHERE sequence_number = expected('4') != actual(5) → affected=0 → 409.
      mockQbExecute.mockResolvedValue({ affected: 0 });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: divergentCid,
          expectedSequenceNumber: '4', // === embeddedSeq - 1 → forward-CAS intent
        })
      ).rejects.toBeInstanceOf(ConflictException);

      // Proves it fell THROUGH the D-05 equivocation guard to the atomic CAS UPDATE —
      // a 400 equivocation would have thrown BEFORE the UPDATE was ever attempted.
      expect(mockQbExecute).toHaveBeenCalled();
    });

    it('allows idempotent republish (embedded = DB seq, SAME CID) without incrementing DB sequenceNumber', async () => {
      // Existing row at seq 5 — TEE re-sign path sends embedded=5n with the SAME CID.
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`, // SAME CID as existing.latestCid
        sequence: 5n, // embedded = DB seq = 5n → idempotent
      });

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid, // SAME CID — genuine idempotent retry
      });

      // The atomic UPDATE setClause uses the SQL no-op expression for idempotent republish.
      const setArgs = mockQbSet.mock.calls[0][0];
      expect(typeof setArgs.sequenceNumber).toBe('function');
      expect(setArgs.sequenceNumber()).toBe('sequence_number');
      // latestCid stays the same-CID value (idempotent retry, not equivocation).
      expect(setArgs.latestCid).toBe(testMetadataCid);
      // Return value reflects unchanged sequence.
      expect(result.sequenceNumber).toBe('5');
      expect(result.success).toBe(true);
    });

    it('allows forward publish (embedded = DB seq + 1) and increments DB sequenceNumber', async () => {
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 6n, // embedded = DB+1 = 6n → forward
      });

      const result = await publishNoCas();
      expect(result).toBeDefined();

      // The atomic UPDATE setClause uses 'sequence_number + 1' SQL expression for forward publish.
      const setArgs = mockQbSet.mock.calls[0][0];
      expect(typeof setArgs.sequenceNumber).toBe('function');
      expect(setArgs.sequenceNumber()).toBe('sequence_number + 1');
      // Return value reflects the computed new sequence.
      expect(result.sequenceNumber).toBe('6');
    });

    it('rejects rollback (embedded < DB seq)', async () => {
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 4n, // 4n < 5n → rollback
      });

      await expect(publishNoCas()).rejects.toThrow(BadRequestException);
      await expect(publishNoCas()).rejects.toThrow(/rollback rejected/i);
    });

    it('rejects wild jump (embedded > DB seq + 1)', async () => {
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 7n, // 7n > 5n+1=6n → wild jump
      });

      await expect(publishNoCas()).rejects.toThrow(BadRequestException);
      await expect(publishNoCas()).rejects.toThrow(/sequence jump rejected/i);
    });

    it('rejects first publish with embedded=2n even when expectedSequenceNumber is undefined (gate runs unconditionally)', async () => {
      // This test explicitly asserts the gate fires WITHOUT a CAS parameter.
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 2n,
      });

      // Call without expectedSequenceNumber — the gate must still fire.
      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          // no expectedSequenceNumber
        })
      ).rejects.toThrow(BadRequestException);
    });

    it('stale expectedSequenceNumber raises 409 when embedded sequence passes D-09', async () => {
      // D-09 (in-memory embedded-sequence gate) runs before the atomic CAS UPDATE.
      // For 409 to fire, the embedded sequence must first pass D-09.
      // Here: embedded=6n = dbSeq+1 passes D-09 (forward publish); the atomic CAS WHERE
      // clause (sequence_number=expected) then fails because expected='3' != actual '5',
      // causing affected=0 → disambiguation findOne → ConflictException.
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 6n, // passes D-09 (forward publish)
      });
      mockQbExecute.mockResolvedValue({ affected: 0 }); // stale CAS → 0 rows updated

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          expectedSequenceNumber: '3', // stale → CAS WHERE fails → 409
        })
      ).rejects.toThrow(ConflictException);
    });
  });

  // =========================================================================
  // D-06: first-publish INSERT-race (Postgres 23505 unique-violation) → 409
  // =========================================================================

  describe('first-publish INSERT-race translation (D-06/SC#4)', () => {
    it('translates a Postgres 23505 unique-violation on first-publish save into ConflictException (409)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 1n,
      });
      // Concurrent first-publish race: another request's INSERT won, this one's
      // save() hits the unique constraint on ipns_name.
      mockFolderIpnsRepo.save.mockRejectedValue({ code: '23505' });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).rejects.toThrow(ConflictException);
    });

    it('re-throws a non-23505 first-publish save error unchanged', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 1n,
      });
      const nonUniqueViolation = { code: '23503' }; // foreign-key violation, not unique
      mockFolderIpnsRepo.save.mockRejectedValue(nonUniqueViolation);

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).rejects.toBe(nonUniqueViolation);
    });
  });

  // =========================================================================
  // D-03: Strict first-publish gate — only embedded 1 accepted (Plan 60-05)
  // =========================================================================

  describe('upsertFolderIpns D-03 strict first-publish gate', () => {
    it('rejects first publish with embedded sequence 0n (D-03: only 1 allowed)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 0n,
      });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).rejects.toThrow(BadRequestException);

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).rejects.toThrow(/embedded sequence must be 1, got 0/);
    });

    it('accepts first publish with embedded sequence 1n (D-03: strict)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 1n,
      });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).resolves.toBeDefined();
    });

    it('forward publish (existing row, embedded = dbSeq + 1) still accepted after D-03', async () => {
      const existingRow = { ...mockFolderEntity, sequenceNumber: '3', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 4n,
      });

      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
        })
      ).resolves.toBeDefined();
    });

    it('idempotent republish (existing row, embedded = dbSeq) still accepted after D-03', async () => {
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 5n,
      });

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe('5');
    });
  });

  // =========================================================================
  // D-06: null signed_record → 404; resolve enrich removal (Plan 60-05)
  // =========================================================================

  describe('resolveRecord D-06 null-signed-record and enrich removal', () => {
    beforeEach(() => {
      mockParseIpnsRecord.mockReset();
    });

    it('resolveRecord with null-signed-record DB row and no network → returns null (404)', async () => {
      // Network finds nothing
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);
      // DB has a row but signedRecord is NULL
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: testMetadataCid,
        sequenceNumber: '5',
        signedRecord: null,
        publicKey: testPublicKeyBytes,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).toBeNull();
    });

    it('resolveRecord with valid signedRecord DB row → returns parsed result (success path unchanged)', async () => {
      const sigBytes = new Uint8Array(64).fill(0xab);
      const dataBytes = new Uint8Array(48).fill(0xcd);
      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: testMetadataCid,
        sequenceNumber: '5',
        signedRecord: signedRecordBytes,
        publicKey: testPublicKeyBytes,
      });
      mockParseIpnsRecord.mockReturnValueOnce({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 4n,
        signatureV2: sigBytes,
        data: dataBytes,
        pubKey: testPublicKeyBytes,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe(testMetadataCid);
      expect(result!.sequenceNumber).toBe('5');
    });

    it('returns a complete record with pubKey from the publicKey column when the network record lacks signature fields at equal sequence (regression: 60-05 enrich removal)', async () => {
      // Realistic Ed25519 case the prior unit test masked: the network record parsed
      // from delegated routing carries NO signature fields, and the parsed signed bytes
      // carry sig + data but NO pubKey. A strict client requires all three, so resolve
      // must serve the authoritative DB record and supply pubKey from the validated
      // publicKey column. Reproduces the SDK-E2E "IPNS resolve returned without signature
      // fields — fail closed" break that mocked-boundary unit tests missed.
      const sigBytes = new Uint8Array(64).fill(0xab);
      const dataBytes = new Uint8Array(48).fill(0xcd);
      const networkBytes = new Uint8Array([7, 8, 9]);
      const signedRecordBytes = new Uint8Array([4, 5, 6]);

      mockDelegatedRoutingClient.resolve.mockResolvedValue(networkBytes);
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: testMetadataCid,
        sequenceNumber: '5',
        signedRecord: signedRecordBytes,
        publicKey: testPublicKeyBytes,
      });

      // 1st parse = network record (no signature fields, equal sequence).
      // 2nd parse = cached signed record (sig + data, but NO pubKey — Ed25519).
      mockParseIpnsRecord
        .mockReturnValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 5n })
        .mockReturnValueOnce({
          value: `/ipfs/${testMetadataCid}`,
          sequence: 4n,
          signatureV2: sigBytes,
          data: dataBytes,
        });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe(testMetadataCid);
      expect(result!.sequenceNumber).toBe('5');
      // The fix: pubKey is supplied from the DB publicKey column so the client can verify.
      expect(result!.pubKey).toBe(testPublicKey);
      expect(result!.signatureV2).toBe(Buffer.from(sigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(dataBytes).toString('base64'));
    });
  });
});
