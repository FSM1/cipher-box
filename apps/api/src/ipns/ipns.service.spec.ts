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
import { parseIpnsRecord, verifyIpnsRecordSignature } from '@cipherbox/crypto';

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
  // Derived from testPublicKeyBytes via deriveIpnsName (must match for server-side validation)
  const testIpnsName = 'k51qzi5uqu5dg7hrs1jyr49oygapxsw71v7pv43rk8lemejo9h2m3hkzvww8io';
  const testMetadataCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
  const testRecord = btoa('test-ipns-record-bytes'); // base64 encoded
  const testRecordBytes = Buffer.from('test-ipns-record-bytes');
  const testPublicKeyBytes = Buffer.from(new Uint8Array(32).map((_, index) => index + 1));
  const testPublicKey = testPublicKeyBytes.toString('base64');
  const testEncryptedIpnsPrivateKey = 'a'.repeat(128); // 64 bytes hex
  const testKeyEpoch = 1;

  const mockFolderEntity: FolderIpns = {
    id: 'folder-id-1',
    userId: testUserId,
    ipnsName: testIpnsName,
    latestCid: testMetadataCid,
    sequenceNumber: '5',
    signedRecord: null,
    publicKey: testPublicKeyBytes,
    encryptedIpnsPrivateKey: Buffer.from(testEncryptedIpnsPrivateKey, 'hex'),
    keyEpoch: testKeyEpoch,
    isRoot: false,
    recordType: 'folder',
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

    // Defaults: records verify, and parse yields a benign sequence (0n) so the
    // anti-rollback check in upsertFolderIpns is a no-op unless a test overrides.
    mockVerifyIpnsRecordSignature.mockResolvedValue(true);
    mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 0n });
  });

  afterEach(() => {
    jest.clearAllMocks();
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
          publicKey: testPublicKeyBytes,
        })
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
      expect(mockFolderIpnsRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          signedRecord: testRecordBytes,
          publicKey: testPublicKeyBytes,
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
          recordType: 'folder',
        })
      );
    });

    it('should increment sequence number for existing folder', async () => {
      const existingFolder = { ...mockFolderEntity, sequenceNumber: '10' };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingFolder);
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));
      // S1 validates embedded CID vs metadataCid — use testMetadataCid so the default
      // parseIpnsRecord mock (value: /ipfs/testMetadataCid) aligns with the DTO value.

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });

      expect(mockFolderIpnsRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          sequenceNumber: '11',
          latestCid: testMetadataCid,
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
      // S1 validates embedded CID vs metadataCid — use testMetadataCid so the default
      // parseIpnsRecord mock aligns with the DTO value.

      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
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
      // S1 validates embedded CID vs metadataCid — use testMetadataCid so the default
      // parseIpnsRecord mock aligns with the DTO value.

      const beforeTest = new Date();
      await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
      });
      const afterTest = new Date();

      const savedEntity = mockFolderIpnsRepo.save.mock.calls[0][0];
      expect(savedEntity.updatedAt.getTime()).toBeGreaterThanOrEqual(beforeTest.getTime());
      expect(savedEntity.updatedAt.getTime()).toBeLessThanOrEqual(afterTest.getTime());
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

    // S1: first-publish tolerance — embedded seq 0n accepted when expectedSequenceNumber='0'
    it('should accept embedded sequence 0n on first publish (tolerance for pre-increment)', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });
      // embedded seq 0n with expectedSequenceNumber '0' → diff is 0n → accepted
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
      ).resolves.toBeDefined();
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
      mockFolderIpnsRepo.save.mockResolvedValue({ ...existingWithRecord, sequenceNumber: '6' });
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
      expect(mockFolderIpnsRepo.save).toHaveBeenCalled();
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

    it('should enrich network signature data with cached publicKey when field 7 is absent', async () => {
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
      expect(result!.pubKey).toBe(testPublicKey);
      expect(result!.signatureV2).toBe(Buffer.from(sigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(dataBytes).toString('base64'));
    });

    it('should enrich network result with cached signature fields when sequences are equal', async () => {
      const mockRecordBytes = new Uint8Array([1, 2, 3]);
      const cachedSigBytes = new Uint8Array(64).fill(0xaa);
      const cachedDataBytes = new Uint8Array(48).fill(0xbb);

      // Network returns record WITHOUT signature fields
      mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
      mockParseIpnsRecord.mockReturnValue({
        value: '/ipfs/bafyNETWORK',
        sequence: 10n,
      });

      // DB cache has same sequence WITH signedRecord containing signature data
      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyNETWORK',
        sequenceNumber: '10',
        signedRecord: signedRecordBytes,
        publicKey: testPublicKeyBytes,
      });

      // parseCachedRecord will call parseIpnsRecordBytes on the signedRecord
      // Second call to mockParseIpnsRecord is for the cached signedRecord
      mockParseIpnsRecord
        .mockReturnValueOnce({
          value: '/ipfs/bafyNETWORK',
          sequence: 10n,
        })
        .mockReturnValueOnce({
          value: '/ipfs/bafyNETWORK',
          sequence: 10n,
          signatureV2: cachedSigBytes,
          data: cachedDataBytes,
        });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('bafyNETWORK');
      expect(result!.sequenceNumber).toBe('10');
      expect(result!.signatureV2).toBe(Buffer.from(cachedSigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(cachedDataBytes).toString('base64'));
      expect(result!.pubKey).toBe(testPublicKey);
    });

    it('should use DB sequenceNumber and CID when signed record contains stale values', async () => {
      // Network fails, so we fall back to DB cache with signedRecord
      mockDelegatedRoutingClient.resolve.mockResolvedValue(null);

      const signedRecordBytes = new Uint8Array([4, 5, 6]);
      const cachedSigBytes = new Uint8Array(64).fill(0xcc);
      const cachedDataBytes = new Uint8Array(48).fill(0xdd);

      // DB has sequence 5 and a newer CID, but signedRecord bytes contain stale seq 0 and old CID
      mockFolderIpnsRepo.findOne.mockResolvedValue({
        ...mockFolderEntity,
        latestCid: 'bafyNEWER',
        sequenceNumber: '5',
        signedRecord: signedRecordBytes,
        publicKey: testPublicKeyBytes,
      });

      // parseCachedRecord will parse the signedRecord bytes — they embed the stale values
      mockParseIpnsRecord.mockReturnValueOnce({
        value: '/ipfs/bafyOLDER',
        sequence: 0n,
        signatureV2: cachedSigBytes,
        data: cachedDataBytes,
      });

      const result = await service.resolveRecord(testIpnsName);

      expect(result).not.toBeNull();
      // DB columns are authoritative, not the parsed signed record
      expect(result!.cid).toBe('bafyNEWER');
      expect(result!.sequenceNumber).toBe('5');
      // Signature fields still come from the parsed record
      expect(result!.signatureV2).toBe(Buffer.from(cachedSigBytes).toString('base64'));
      expect(result!.data).toBe(Buffer.from(cachedDataBytes).toString('base64'));
      expect(result!.pubKey).toBe(testPublicKey);
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
          signedRecord: null,
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
        signedRecord: null,
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
      mockFolderIpnsRepo.save.mockResolvedValue(mockFolderEntity);
      mockDelegatedRoutingClient.publish.mockRejectedValue(
        new HttpException('Failed to publish', HttpStatus.BAD_GATEWAY)
      );

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
      // S1 sequence check: expects embedded = expectedSeq + 1n = 6n
      mockParseIpnsRecord.mockResolvedValue({ value: `/ipfs/${testMetadataCid}`, sequence: 6n });

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
      // S1 CID check: all records use testMetadataCid so the default mock aligns

      const batchDto: BatchPublishIpnsDto = {
        records: [
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00001',
            record: testRecord,
            metadataCid: testMetadataCid, // S1: matches embedded CID from default mock
            recordType: 'file',
          },
          {
            ipnsName: 'k51qzi5uqu5dg12345abcdef00002',
            record: testRecord,
            metadataCid: testMetadataCid, // S1: matches embedded CID from default mock
            recordType: 'file',
          },
          {
            ipnsName: testIpnsName,
            record: testRecord,
            metadataCid: testMetadataCid,
            recordType: 'folder',
            expectedSequenceNumber: '3', // Stale: DB has '5' → CAS 409 fires first
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
      // S1 sequence check for the folder expects embedded = 5 + 1 = 6n. The file record
      // has no expectedSequenceNumber, so its S1 seq check is skipped and any sequence is
      // fine. Both records share `testRecord` bytes and the records publish concurrently —
      // `Promise.allSettled` preserves RESULT order, not the order each call reaches
      // parseIpnsRecord — so an order-keyed mock would flake. Return a single value that
      // satisfies both (CID matches; sequence 6n satisfies the folder, ignored by the file).
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
            recordType: 'file',
          },
          {
            ipnsName: testIpnsName,
            record: testRecord,
            metadataCid: testMetadataCid,
            recordType: 'folder',
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
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '6' });

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
      // The canonical row keeps its original creator (userId is not reassigned).
      const saved = mockFolderIpnsRepo.save.mock.calls[0][0];
      expect(saved.userId).toBe(testUserId);
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
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '6' });

      const dto: PublishIpnsDto = {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: testMetadataCid,
        encryptedIpnsPrivateKey: 'bb'.repeat(64),
        keyEpoch: 2,
      };

      await service.publishRecord(otherUser, dto);

      // Enrollment fields stay as the creator's (existing.userId !== publisher).
      const saved = mockFolderIpnsRepo.save.mock.calls[0][0];
      expect(saved.encryptedIpnsPrivateKey).toEqual(
        Buffer.from(testEncryptedIpnsPrivateKey, 'hex')
      );
      expect(saved.keyEpoch).toBe(testKeyEpoch);
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
      mockFolderIpnsRepo.save.mockResolvedValue({ ...stored, sequenceNumber: '10' });
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

    it('allows first publish with embedded sequence 0n', async () => {
      mockFolderIpnsRepo.findOne.mockResolvedValue(null);
      mockFolderIpnsRepo.create.mockReturnValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockFolderIpnsRepo.save.mockResolvedValue({ ...mockFolderEntity, sequenceNumber: '1' });
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 0n,
      });

      await expect(publishNoCas()).resolves.toBeDefined();
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

    it('allows idempotent republish (embedded = DB seq) without incrementing DB sequenceNumber', async () => {
      // Existing row at seq 5 — TEE re-sign path sends embedded=5n.
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));
      const newCid = 'bafkreinewcidforteeresign000000000000000000000000000000000000000';
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${newCid}`,
        sequence: 5n, // embedded = DB seq = 5n → idempotent
      });

      const result = await service.publishRecord(testUserId, {
        ipnsName: testIpnsName,
        record: testRecord,
        metadataCid: newCid, // new CID (TEE may re-sign after content update)
      });

      // DB sequenceNumber must stay at '5' — not incremented.
      const savedEntity = mockFolderIpnsRepo.save.mock.calls[0][0];
      expect(savedEntity.sequenceNumber).toBe('5');
      // But latestCid must be updated (Pitfall 4 — idempotent still updates CID).
      expect(savedEntity.latestCid).toBe(newCid);
      expect(result.success).toBe(true);
    });

    it('allows forward publish (embedded = DB seq + 1) and increments DB sequenceNumber', async () => {
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      mockFolderIpnsRepo.save.mockImplementation((entity) => Promise.resolve(entity));
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 6n, // embedded = DB+1 = 6n → forward
      });

      await expect(publishNoCas()).resolves.toBeDefined();

      const savedEntity = mockFolderIpnsRepo.save.mock.calls[0][0];
      expect(savedEntity.sequenceNumber).toBe('6');
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

    it('CAS-409 takes precedence over D-09 when expectedSequenceNumber is stale', async () => {
      // Existing row at seq 5; CAS expected='3' (stale) → 409 fires before D-09 400.
      // Even if the embedded sequence would also trigger D-09, the 409 should win.
      const existingRow = { ...mockFolderEntity, sequenceNumber: '5', signedRecord: null };
      mockFolderIpnsRepo.findOne.mockResolvedValue(existingRow);
      // Embedded sequence that would trigger D-09 rollback (4n < 5n)
      mockParseIpnsRecord.mockResolvedValue({
        value: `/ipfs/${testMetadataCid}`,
        sequence: 4n,
      });

      // The CAS check fires first and throws 409, not D-09 400.
      await expect(
        service.publishRecord(testUserId, {
          ipnsName: testIpnsName,
          record: testRecord,
          metadataCid: testMetadataCid,
          expectedSequenceNumber: '3', // stale → CAS 409
        })
      ).rejects.toThrow(ConflictException);
    });
  });
});
