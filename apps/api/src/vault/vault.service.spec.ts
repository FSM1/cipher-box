import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { VaultService, QUOTA_LIMIT_BYTES } from './vault.service';
import { Vault } from './entities/vault.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { InitVaultDto } from './dto/init-vault.dto';

describe('VaultService', () => {
  let service: VaultService;
  let mockVaultRepo: {
    findOne: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    update: jest.Mock;
  };
  let mockQueryBuilder: {
    select: jest.Mock;
    where: jest.Mock;
    getRawOne: jest.Mock;
    insert: jest.Mock;
    into: jest.Mock;
    values: jest.Mock;
    orIgnore: jest.Mock;
    execute: jest.Mock;
  };
  let mockPinnedCidRepo: {
    createQueryBuilder: jest.Mock;
    delete: jest.Mock;
  };

  // Test data
  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testVaultId = '660e8400-e29b-41d4-a716-446655440001';
  const testOwnerPublicKey = '04' + 'a'.repeat(128); // 65 bytes uncompressed pubkey
  const testEncryptedRootFolderKey = 'b'.repeat(64);
  const testEncryptedRootIpnsPrivateKey = 'c'.repeat(128);
  const testRootIpnsName = 'k51qzi5uqu5dg12345';

  const mockVaultEntity: Vault = {
    id: testVaultId,
    ownerId: testUserId,
    ownerPublicKey: Buffer.from(testOwnerPublicKey, 'hex'),
    encryptedRootFolderKey: Buffer.from(testEncryptedRootFolderKey, 'hex'),
    encryptedRootIpnsPrivateKey: Buffer.from(testEncryptedRootIpnsPrivateKey, 'hex'),
    rootIpnsName: testRootIpnsName,
    createdAt: new Date('2026-01-20T12:00:00.000Z'),
    initializedAt: null,
    updatedAt: new Date('2026-01-20T12:00:00.000Z'),
    owner: {} as any,
  };

  const testInitVaultDto: InitVaultDto = {
    ownerPublicKey: testOwnerPublicKey,
    encryptedRootFolderKey: testEncryptedRootFolderKey,
    encryptedRootIpnsPrivateKey: testEncryptedRootIpnsPrivateKey,
    rootIpnsName: testRootIpnsName,
  };

  beforeEach(async () => {
    // Initialize mock objects fresh for each test
    mockQueryBuilder = {
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      getRawOne: jest.fn(),
      insert: jest.fn().mockReturnThis(),
      into: jest.fn().mockReturnThis(),
      values: jest.fn().mockReturnThis(),
      orIgnore: jest.fn().mockReturnThis(),
      execute: jest.fn(),
    };

    mockVaultRepo = {
      findOne: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
    };

    mockPinnedCidRepo = {
      createQueryBuilder: jest.fn().mockReturnValue(mockQueryBuilder),
      delete: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VaultService,
        {
          provide: getRepositoryToken(Vault),
          useValue: mockVaultRepo,
        },
        {
          provide: getRepositoryToken(PinnedCid),
          useValue: mockPinnedCidRepo,
        },
      ],
    }).compile();

    service = module.get<VaultService>(VaultService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('QUOTA_LIMIT_BYTES constant', () => {
    it('should export QUOTA_LIMIT_BYTES as 500 MiB', () => {
      expect(QUOTA_LIMIT_BYTES).toBe(500 * 1024 * 1024);
      expect(QUOTA_LIMIT_BYTES).toBe(524288000);
    });
  });

  describe('initializeVault', () => {
    it('should create vault for new user', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);
      mockVaultRepo.create.mockReturnValue(mockVaultEntity);
      mockVaultRepo.save.mockResolvedValue(mockVaultEntity);

      const result = await service.initializeVault(testUserId, testInitVaultDto);

      expect(mockVaultRepo.findOne).toHaveBeenCalledWith({
        where: { ownerId: testUserId },
      });
      expect(mockVaultRepo.create).toHaveBeenCalledWith({
        ownerId: testUserId,
        ownerPublicKey: Buffer.from(testOwnerPublicKey, 'hex'),
        encryptedRootFolderKey: Buffer.from(testEncryptedRootFolderKey, 'hex'),
        encryptedRootIpnsPrivateKey: Buffer.from(testEncryptedRootIpnsPrivateKey, 'hex'),
        rootIpnsName: testRootIpnsName,
        initializedAt: null,
      });
      expect(mockVaultRepo.save).toHaveBeenCalled();
      expect(result.id).toBe(testVaultId);
      expect(result.ownerPublicKey).toBe(testOwnerPublicKey);
    });

    it('should decode hex strings to buffers correctly', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);
      mockVaultRepo.create.mockReturnValue(mockVaultEntity);
      mockVaultRepo.save.mockResolvedValue(mockVaultEntity);

      await service.initializeVault(testUserId, testInitVaultDto);

      const createCall = mockVaultRepo.create.mock.calls[0][0];
      expect(Buffer.isBuffer(createCall.ownerPublicKey)).toBe(true);
      expect(Buffer.isBuffer(createCall.encryptedRootFolderKey)).toBe(true);
      expect(Buffer.isBuffer(createCall.encryptedRootIpnsPrivateKey)).toBe(true);
    });

    it('should throw ConflictException if vault already exists', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);

      await expect(service.initializeVault(testUserId, testInitVaultDto)).rejects.toThrow(
        ConflictException
      );
      await expect(service.initializeVault(testUserId, testInitVaultDto)).rejects.toThrow(
        'Vault already exists for this user'
      );
      expect(mockVaultRepo.create).not.toHaveBeenCalled();
      expect(mockVaultRepo.save).not.toHaveBeenCalled();
    });

    it('should handle valid hex strings of various lengths', async () => {
      const shortHexDto: InitVaultDto = {
        ownerPublicKey: 'aabb',
        encryptedRootFolderKey: 'ccdd',
        encryptedRootIpnsPrivateKey: 'eeff',
        rootIpnsName: testRootIpnsName,
      };

      const shortVault = {
        ...mockVaultEntity,
        ownerPublicKey: Buffer.from('aabb', 'hex'),
        encryptedRootFolderKey: Buffer.from('ccdd', 'hex'),
        encryptedRootIpnsPrivateKey: Buffer.from('eeff', 'hex'),
      };

      mockVaultRepo.findOne.mockResolvedValue(null);
      mockVaultRepo.create.mockReturnValue(shortVault);
      mockVaultRepo.save.mockResolvedValue(shortVault);

      const result = await service.initializeVault(testUserId, shortHexDto);

      expect(result.ownerPublicKey).toBe('aabb');
      expect(result.encryptedRootFolderKey).toBe('ccdd');
      expect(result.encryptedRootIpnsPrivateKey).toBe('eeff');
    });
  });

  describe('getVault', () => {
    it('should return vault response DTO with hex-encoded fields', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);

      const result = await service.getVault(testUserId);

      expect(mockVaultRepo.findOne).toHaveBeenCalledWith({
        where: { ownerId: testUserId },
      });
      expect(result).toEqual({
        id: testVaultId,
        ownerPublicKey: testOwnerPublicKey,
        encryptedRootFolderKey: testEncryptedRootFolderKey,
        encryptedRootIpnsPrivateKey: testEncryptedRootIpnsPrivateKey,
        rootIpnsName: testRootIpnsName,
        createdAt: mockVaultEntity.createdAt,
        initializedAt: null,
      });
    });

    it('should throw NotFoundException if vault does not exist', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);

      await expect(service.getVault(testUserId)).rejects.toThrow(NotFoundException);
      await expect(service.getVault(testUserId)).rejects.toThrow('Vault not found');
    });
  });

  describe('findVault', () => {
    it('should return vault response DTO if found', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);

      const result = await service.findVault(testUserId);

      expect(mockVaultRepo.findOne).toHaveBeenCalledWith({
        where: { ownerId: testUserId },
      });
      expect(result).not.toBeNull();
      expect(result?.id).toBe(testVaultId);
      expect(result?.ownerPublicKey).toBe(testOwnerPublicKey);
    });

    it('should return null if vault not found', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);

      const result = await service.findVault(testUserId);

      expect(result).toBeNull();
    });
  });

  describe('getQuota', () => {
    it('should calculate quota from SUM of pinned CIDs', async () => {
      const usedBytes = 104857600; // 100 MiB
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: usedBytes.toString() });

      const result = await service.getQuota(testUserId);

      expect(mockPinnedCidRepo.createQueryBuilder).toHaveBeenCalledWith('pin');
      expect(mockQueryBuilder.select).toHaveBeenCalledWith(
        'COALESCE(SUM(pin.size_bytes), 0)',
        'total'
      );
      expect(mockQueryBuilder.where).toHaveBeenCalledWith('pin.user_id = :userId', {
        userId: testUserId,
      });
      expect(result).toEqual({
        usedBytes,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: QUOTA_LIMIT_BYTES - usedBytes,
      });
    });

    it('should return full quota when no pins exist (total = 0)', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: '0' });

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: 0,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: QUOTA_LIMIT_BYTES,
      });
    });

    it('should return 0 remaining when at limit', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: QUOTA_LIMIT_BYTES.toString() });

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: QUOTA_LIMIT_BYTES,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: 0,
      });
    });

    it('should handle null result from getRawOne', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue(null);

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: 0,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: QUOTA_LIMIT_BYTES,
      });
    });

    it('should handle undefined total from getRawOne', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: undefined });

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: 0,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: QUOTA_LIMIT_BYTES,
      });
    });

    it('should handle very large byte values (approaching 500 MiB)', async () => {
      const nearLimit = QUOTA_LIMIT_BYTES - 1024; // 1KB under limit
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: nearLimit.toString() });

      const result = await service.getQuota(testUserId);

      expect(result.usedBytes).toBe(nearLimit);
      expect(result.remainingBytes).toBe(1024);
    });

    it('should correctly calculate remainingBytes as max(0, limit - used) when over limit', async () => {
      const overLimit = QUOTA_LIMIT_BYTES + 1000;
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: overLimit.toString() });

      const result = await service.getQuota(testUserId);

      expect(result.usedBytes).toBe(overLimit);
      expect(result.remainingBytes).toBe(0); // Math.max(0, limit - used)
    });
  });

  describe('checkQuota', () => {
    it('should return true if usage + additional <= limit', async () => {
      const usedBytes = 100 * 1024 * 1024; // 100 MiB
      const additional = 50 * 1024 * 1024; // 50 MiB
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: usedBytes.toString() });

      const result = await service.checkQuota(testUserId, additional);

      expect(result).toBe(true);
    });

    it('should return false if usage + additional > limit', async () => {
      const usedBytes = 450 * 1024 * 1024; // 450 MiB
      const additional = 100 * 1024 * 1024; // 100 MiB - would exceed 500 MiB limit
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: usedBytes.toString() });

      const result = await service.checkQuota(testUserId, additional);

      expect(result).toBe(false);
    });

    it('should return true at exact limit boundary', async () => {
      const usedBytes = 400 * 1024 * 1024; // 400 MiB
      const additional = 100 * 1024 * 1024; // 100 MiB - exactly at 500 MiB limit
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: usedBytes.toString() });

      const result = await service.checkQuota(testUserId, additional);

      expect(result).toBe(true);
    });

    it('should handle 0 additionalBytes (always true if under limit)', async () => {
      const usedBytes = 100 * 1024 * 1024;
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: usedBytes.toString() });

      const result = await service.checkQuota(testUserId, 0);

      expect(result).toBe(true);
    });

    it('should handle full storage scenario', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: QUOTA_LIMIT_BYTES.toString() });

      const result = await service.checkQuota(testUserId, 1); // Even 1 byte should fail

      expect(result).toBe(false);
    });
  });

  describe('recordPin', () => {
    it('should insert pin record with upsert (orIgnore)', async () => {
      const testCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
      const sizeBytes = 1024;
      mockQueryBuilder.execute.mockResolvedValue({ affected: 1 });

      await service.recordPin(testUserId, testCid, sizeBytes);

      expect(mockPinnedCidRepo.createQueryBuilder).toHaveBeenCalled();
      expect(mockQueryBuilder.insert).toHaveBeenCalled();
      expect(mockQueryBuilder.into).toHaveBeenCalledWith(PinnedCid);
      expect(mockQueryBuilder.values).toHaveBeenCalledWith({
        userId: testUserId,
        cid: testCid,
        sizeBytes: sizeBytes.toString(),
      });
      expect(mockQueryBuilder.orIgnore).toHaveBeenCalled();
      expect(mockQueryBuilder.execute).toHaveBeenCalled();
    });

    it('should convert sizeBytes to string for bigint column', async () => {
      const testCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
      const sizeBytes = 104857600; // 100 MiB
      mockQueryBuilder.execute.mockResolvedValue({ affected: 1 });

      await service.recordPin(testUserId, testCid, sizeBytes);

      const valuesCall = mockQueryBuilder.values.mock.calls[0][0];
      expect(typeof valuesCall.sizeBytes).toBe('string');
      expect(valuesCall.sizeBytes).toBe('104857600');
    });

    it('should handle duplicate pin gracefully (orIgnore)', async () => {
      const testCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
      mockQueryBuilder.execute.mockResolvedValue({ affected: 0 }); // No rows affected due to conflict

      // Should not throw
      await expect(service.recordPin(testUserId, testCid, 1024)).resolves.toBeUndefined();
    });
  });

  describe('recordUnpin', () => {
    it('should delete pin by userId and cid', async () => {
      const testCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
      mockPinnedCidRepo.delete.mockResolvedValue({ affected: 1 });

      await service.recordUnpin(testUserId, testCid);

      expect(mockPinnedCidRepo.delete).toHaveBeenCalledWith({
        userId: testUserId,
        cid: testCid,
      });
    });

    it('should not throw if pin not found (idempotent)', async () => {
      const testCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
      mockPinnedCidRepo.delete.mockResolvedValue({ affected: 0 }); // No rows deleted

      // Should not throw - idempotent behavior
      await expect(service.recordUnpin(testUserId, testCid)).resolves.toBeUndefined();
    });
  });

  describe('markInitialized', () => {
    it('should update vault with initializedAt timestamp', async () => {
      mockVaultRepo.update.mockResolvedValue({ affected: 1 });

      const beforeCall = new Date();
      await service.markInitialized(testUserId);
      const afterCall = new Date();

      expect(mockVaultRepo.update).toHaveBeenCalledWith(
        { ownerId: testUserId },
        expect.objectContaining({
          initializedAt: expect.any(Date),
        })
      );

      // Verify the timestamp is reasonable
      const updateCall = mockVaultRepo.update.mock.calls[0][1];
      expect(updateCall.initializedAt.getTime()).toBeGreaterThanOrEqual(beforeCall.getTime());
      expect(updateCall.initializedAt.getTime()).toBeLessThanOrEqual(afterCall.getTime());
    });
  });

  describe('toVaultResponse (tested indirectly)', () => {
    it('should hex-encode all buffer fields via getVault', async () => {
      const vaultWithInitialized = {
        ...mockVaultEntity,
        initializedAt: new Date('2026-01-20T13:00:00.000Z'),
      };
      mockVaultRepo.findOne.mockResolvedValue(vaultWithInitialized);

      const result = await service.getVault(testUserId);

      // Verify hex encoding
      expect(result.ownerPublicKey).toBe(mockVaultEntity.ownerPublicKey.toString('hex'));
      expect(result.encryptedRootFolderKey).toBe(
        mockVaultEntity.encryptedRootFolderKey.toString('hex')
      );
      expect(result.encryptedRootIpnsPrivateKey).toBe(
        mockVaultEntity.encryptedRootIpnsPrivateKey.toString('hex')
      );
      expect(result.initializedAt).toEqual(vaultWithInitialized.initializedAt);
    });

    it('should preserve all non-buffer fields via findVault', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);

      const result = await service.findVault(testUserId);

      expect(result?.id).toBe(mockVaultEntity.id);
      expect(result?.rootIpnsName).toBe(mockVaultEntity.rootIpnsName);
      expect(result?.createdAt).toBe(mockVaultEntity.createdAt);
      expect(result?.initializedAt).toBe(mockVaultEntity.initializedAt);
    });
  });
});
