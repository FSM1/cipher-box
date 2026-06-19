import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { VaultService, QUOTA_LIMIT_BYTES } from './vault.service';
import { Vault } from './entities/vault.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { PendingUnpin } from './entities/pending-unpin.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { TeeKeyStateService } from '../tee/tee-key-state.service';
import { MetricsService } from '../metrics/metrics.service';
import { InitVaultDto } from './dto/init-vault.dto';
import { IPFS_PROVIDER } from '../ipfs/providers';

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
  let mockFolderIpnsRepo: {
    create: jest.Mock;
    save: jest.Mock;
    update: jest.Mock;
  };
  let mockUserRepo: {
    findOne: jest.Mock;
  };
  let mockTeeKeyStateService: {
    getTeeKeysDto: jest.Mock;
  };
  let mockConfigService: {
    get: jest.Mock;
  };

  // guardedUnpin mocks
  let mockDataSource: {
    transaction: jest.Mock;
  };
  let mockManager: {
    getRepository: jest.Mock;
    query: jest.Mock;
    createQueryBuilder: jest.Mock;
  };
  let mockManagerPinnedCidRepo: {
    findOne: jest.Mock;
    delete: jest.Mock;
  };
  let mockManagerPendingUnpinRepo: {
    createQueryBuilder: jest.Mock;
  };
  let mockManagerQueryBuilder: {
    select: jest.Mock;
    where: jest.Mock;
    getRawOne: jest.Mock;
    insert: jest.Mock;
    into: jest.Mock;
    values: jest.Mock;
    orIgnore: jest.Mock;
    execute: jest.Mock;
  };
  let mockIpfsProvider: {
    unpinFile: jest.Mock;
  };
  let mockMetricsService: {
    unpinCrossUserAttempts: { inc: jest.Mock };
    fileUnpins: { inc: jest.Mock };
  };
  let mockPendingUnpinRepository: {
    delete: jest.Mock;
  };

  // Test data
  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testVaultId = '660e8400-e29b-41d4-a716-446655440001';
  const testOwnerPublicKey = '04' + 'a'.repeat(128); // 65 bytes uncompressed pubkey
  const testRootIpnsName = 'k51qzi5uqu5dg12345';
  const mockVaultEntity: Vault = {
    id: testVaultId,
    ownerId: testUserId,
    ownerPublicKey: Buffer.from(testOwnerPublicKey, 'hex'),
    rootIpnsName: testRootIpnsName,
    isByoUser: false,
    createdAt: new Date('2026-01-20T12:00:00.000Z'),
    initializedAt: null,
    updatedAt: new Date('2026-01-20T12:00:00.000Z'),
    owner: {} as unknown as User,
  };

  const testInitVaultDto: InitVaultDto = {
    ownerPublicKey: testOwnerPublicKey,
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

    mockFolderIpnsRepo = {
      create: jest.fn().mockImplementation((data) => data),
      save: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({ affected: 1 }),
    };

    mockUserRepo = {
      findOne: jest.fn(),
    };

    mockTeeKeyStateService = {
      getTeeKeysDto: jest.fn().mockResolvedValue(null),
    };

    mockConfigService = {
      get: jest.fn().mockImplementation((key: string, defaultValue?: unknown) => {
        if (key === 'RECYCLE_BIN_RETENTION_DAYS') return defaultValue;
        return defaultValue;
      }),
    };

    // Initialize guardedUnpin mocks
    mockManagerQueryBuilder = {
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      getRawOne: jest.fn().mockResolvedValue({ count: '0' }),
      insert: jest.fn().mockReturnThis(),
      into: jest.fn().mockReturnThis(),
      values: jest.fn().mockReturnThis(),
      orIgnore: jest.fn().mockReturnThis(),
      execute: jest.fn().mockResolvedValue({}),
    };

    mockManagerPinnedCidRepo = {
      findOne: jest.fn(),
      delete: jest.fn().mockResolvedValue({ affected: 1 }),
    };

    mockManagerPendingUnpinRepo = {
      createQueryBuilder: jest.fn().mockReturnValue(mockManagerQueryBuilder),
    };

    mockManager = {
      getRepository: jest.fn().mockImplementation((Entity: unknown) => {
        if (Entity === PinnedCid) return mockManagerPinnedCidRepo;
        if (Entity === PendingUnpin) return mockManagerPendingUnpinRepo;
        return {};
      }),
      query: jest.fn().mockImplementation((sql: string) => {
        if (sql.includes('hashtext')) return Promise.resolve([{ h: '123456789' }]);
        return Promise.resolve([]);
      }),
      createQueryBuilder: jest.fn().mockReturnValue(mockManagerQueryBuilder),
    };

    mockDataSource = {
      transaction: jest
        .fn()
        .mockImplementation(async (cb: (manager: unknown) => Promise<unknown>) => {
          return cb(mockManager);
        }),
    };

    mockIpfsProvider = {
      unpinFile: jest.fn().mockResolvedValue(undefined),
    };

    mockMetricsService = {
      unpinCrossUserAttempts: { inc: jest.fn() },
      fileUnpins: { inc: jest.fn() },
    };

    mockPendingUnpinRepository = {
      delete: jest.fn().mockResolvedValue({ affected: 1 }),
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
        {
          provide: getRepositoryToken(FolderIpns),
          useValue: mockFolderIpnsRepo,
        },
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepo,
        },
        {
          provide: getRepositoryToken(PendingUnpin),
          useValue: mockPendingUnpinRepository,
        },
        {
          provide: TeeKeyStateService,
          useValue: mockTeeKeyStateService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: DataSource,
          useValue: mockDataSource,
        },
        {
          provide: IPFS_PROVIDER,
          useValue: mockIpfsProvider,
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
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
        rootIpnsName: testRootIpnsName,
        initializedAt: null,
      });
      expect(mockVaultRepo.save).toHaveBeenCalled();
      // Verify root folder IPNS entry is created
      expect(mockFolderIpnsRepo.create).toHaveBeenCalledWith({
        userId: testUserId,
        ipnsName: testRootIpnsName,
        latestCid: null,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: null,
        keyEpoch: null,
        isRoot: true,
      });
      expect(mockFolderIpnsRepo.save).toHaveBeenCalled();
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
      expect(mockFolderIpnsRepo.create).not.toHaveBeenCalled();
      expect(mockFolderIpnsRepo.save).not.toHaveBeenCalled();
    });

    it('should handle valid hex strings of various lengths', async () => {
      const shortHexDto: InitVaultDto = {
        ownerPublicKey: 'aabb',
        rootIpnsName: testRootIpnsName,
      };

      const shortVault = {
        ...mockVaultEntity,
        ownerPublicKey: Buffer.from('aabb', 'hex'),
      };

      mockVaultRepo.findOne.mockResolvedValue(null);
      mockVaultRepo.create.mockReturnValue(shortVault);
      mockVaultRepo.save.mockResolvedValue(shortVault);

      const result = await service.initializeVault(testUserId, shortHexDto);

      expect(result.ownerPublicKey).toBe('aabb');
    });

    it('should update isRoot when folder_ipns row already exists from IPNS publish', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);
      mockVaultRepo.create.mockReturnValue(mockVaultEntity);
      mockVaultRepo.save.mockResolvedValue(mockVaultEntity);

      // Simulate duplicate key constraint (PG error code 23505) on folder_ipns save
      mockFolderIpnsRepo.save.mockRejectedValueOnce(
        Object.assign(new Error('duplicate key value violates unique constraint'), {
          code: '23505',
        })
      );

      const result = await service.initializeVault(testUserId, testInitVaultDto);

      expect(mockFolderIpnsRepo.update).toHaveBeenCalledWith(
        { userId: testUserId, ipnsName: testRootIpnsName },
        { isRoot: true }
      );
      expect(result.id).toBe(testVaultId);
    });

    it('should rethrow non-duplicate-key errors from folder_ipns save', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);
      mockVaultRepo.create.mockReturnValue(mockVaultEntity);
      mockVaultRepo.save.mockResolvedValue(mockVaultEntity);

      mockFolderIpnsRepo.save.mockRejectedValueOnce(new Error('connection refused'));

      await expect(service.initializeVault(testUserId, testInitVaultDto)).rejects.toThrow(
        'connection refused'
      );
      expect(mockFolderIpnsRepo.update).not.toHaveBeenCalled();
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
        rootIpnsName: testRootIpnsName,
        createdAt: mockVaultEntity.createdAt,
        initializedAt: null,
        teeKeys: null,
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
        advisory: false,
      });
    });

    it('should return full quota when no pins exist (total = 0)', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: '0' });

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: 0,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: QUOTA_LIMIT_BYTES,
        advisory: false,
      });
    });

    it('should return 0 remaining when at limit', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: QUOTA_LIMIT_BYTES.toString() });

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: QUOTA_LIMIT_BYTES,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: 0,
        advisory: false,
      });
    });

    it('should handle null result from getRawOne', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue(null);

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: 0,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: QUOTA_LIMIT_BYTES,
        advisory: false,
      });
    });

    it('should handle undefined total from getRawOne', async () => {
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: undefined });

      const result = await service.getQuota(testUserId);

      expect(result).toEqual({
        usedBytes: 0,
        limitBytes: QUOTA_LIMIT_BYTES,
        remainingBytes: QUOTA_LIMIT_BYTES,
        advisory: false,
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

  // IN-03: recordUnpin test block removed — the method was deleted from VaultService
  // (zero production callers; all unpin paths go through guardedUnpin).

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

    it('should include teeKeys when TeeKeyStateService returns non-null', async () => {
      const mockTeeKeys = {
        currentEpoch: 1,
        currentPublicKey: '04' + 'ab'.repeat(64),
        previousEpoch: null,
        previousPublicKey: null,
      };
      mockTeeKeyStateService.getTeeKeysDto.mockResolvedValue(mockTeeKeys);
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);

      const result = await service.getVault(testUserId);

      expect(result.teeKeys).toEqual(mockTeeKeys);
    });

    it('should pass null teeKeys when TeeKeyStateService returns null', async () => {
      mockTeeKeyStateService.getTeeKeysDto.mockResolvedValue(null);
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);

      const result = await service.getVault(testUserId);

      expect(result.teeKeys).toBeNull();
    });
  });

  describe('getConfig', () => {
    it('should return recycleBinRetentionDays parsed from env string', () => {
      mockConfigService.get.mockReturnValue('14');

      const result = service.getConfig();

      expect(mockConfigService.get).toHaveBeenCalledWith('RECYCLE_BIN_RETENTION_DAYS');
      expect(result).toEqual({ recycleBinRetentionDays: 14 });
    });

    it('should use default value of 30 when env var is not set', () => {
      mockConfigService.get.mockReturnValue(undefined);

      const result = service.getConfig();

      expect(result).toEqual({ recycleBinRetentionDays: 30 });
    });

    it('should use default value of 30 when env var is invalid', () => {
      mockConfigService.get.mockReturnValue('not-a-number');

      const result = service.getConfig();

      expect(result).toEqual({ recycleBinRetentionDays: 30 });
    });

    it('should use default value of 30 when env var is negative', () => {
      mockConfigService.get.mockReturnValue('-5');

      const result = service.getConfig();

      expect(result).toEqual({ recycleBinRetentionDays: 30 });
    });

    it('should accept zero as valid retention days', () => {
      mockConfigService.get.mockReturnValue('0');

      const result = service.getConfig();

      expect(result).toEqual({ recycleBinRetentionDays: 0 });
    });
  });

  describe('getExportData', () => {
    it('should return export DTO with rootIpnsName and derivation method', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);
      mockUserRepo.findOne.mockResolvedValue({
        id: testUserId,
      });

      const result = await service.getExportData(testUserId);

      expect(result.format).toBe('cipherbox-vault-export');
      expect(result.version).toBe('1.0');
      expect(result.rootIpnsName).toBe(testRootIpnsName);
      expect(result.exportedAt).toBeDefined();
      expect(result.derivationMethod).toBe('web3auth');
    });

    it('should return web3auth derivation method for all users (Core Kit)', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);
      mockUserRepo.findOne.mockResolvedValue({
        id: testUserId,
      });

      const result = await service.getExportData(testUserId);

      expect(result.derivationMethod).toBe('web3auth');
    });

    it('should return null derivationMethod when user not found', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);
      mockUserRepo.findOne.mockResolvedValue(null);

      const result = await service.getExportData(testUserId);

      expect(result.derivationMethod).toBeNull();
    });

    it('should throw NotFoundException if vault does not exist', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);

      await expect(service.getExportData(testUserId)).rejects.toThrow(NotFoundException);
      await expect(service.getExportData(testUserId)).rejects.toThrow('Vault not found');
    });

    it('should include ISO 8601 exportedAt timestamp', async () => {
      mockVaultRepo.findOne.mockResolvedValue(mockVaultEntity);
      mockUserRepo.findOne.mockResolvedValue({ id: testUserId });

      const before = new Date().toISOString();
      const result = await service.getExportData(testUserId);
      const after = new Date().toISOString();

      expect(result.exportedAt >= before).toBe(true);
      expect(result.exportedAt <= after).toBe(true);
    });
  });

  describe('isUserByo', () => {
    it('should return false when vault isByoUser is false', async () => {
      mockVaultRepo.findOne.mockResolvedValue({ isByoUser: false });

      const result = await service.isUserByo(testUserId);

      expect(result).toBe(false);
      expect(mockVaultRepo.findOne).toHaveBeenCalledWith({
        where: { ownerId: testUserId },
        select: ['isByoUser'],
      });
    });

    it('should return true when vault isByoUser is true', async () => {
      mockVaultRepo.findOne.mockResolvedValue({ isByoUser: true });

      const result = await service.isUserByo(testUserId);

      expect(result).toBe(true);
    });

    it('should return false when vault not found', async () => {
      mockVaultRepo.findOne.mockResolvedValue(null);

      const result = await service.isUserByo(testUserId);

      expect(result).toBe(false);
    });
  });

  describe('setByoStatus', () => {
    it('should update isByoUser to true', async () => {
      mockVaultRepo.update.mockResolvedValue({ affected: 1 } as never);

      await service.setByoStatus(testUserId, true);

      expect(mockVaultRepo.update).toHaveBeenCalledWith(
        { ownerId: testUserId },
        { isByoUser: true }
      );
    });

    it('should update isByoUser to false', async () => {
      mockVaultRepo.update.mockResolvedValue({ affected: 1 } as never);

      await service.setByoStatus(testUserId, false);

      expect(mockVaultRepo.update).toHaveBeenCalledWith(
        { ownerId: testUserId },
        { isByoUser: false }
      );
    });
  });

  describe('checkQuota (BYO)', () => {
    it('should return true regardless of usage when user is BYO', async () => {
      // User is BYO -- over quota but should still pass
      mockVaultRepo.findOne.mockResolvedValue({ isByoUser: true });
      mockQueryBuilder.getRawOne.mockResolvedValue({
        total: (QUOTA_LIMIT_BYTES + 1000).toString(),
      });

      const result = await service.checkQuota(testUserId, 100 * 1024 * 1024);

      expect(result).toBe(true);
    });

    it('should enforce quota limit for non-BYO users', async () => {
      // User is NOT BYO -- over quota should fail
      mockVaultRepo.findOne.mockResolvedValue({ isByoUser: false });
      mockQueryBuilder.getRawOne.mockResolvedValue({
        total: (450 * 1024 * 1024).toString(),
      });

      const result = await service.checkQuota(testUserId, 100 * 1024 * 1024);

      expect(result).toBe(false);
    });
  });

  describe('getQuota (advisory flag)', () => {
    it('should return advisory: true for BYO users', async () => {
      mockVaultRepo.findOne.mockResolvedValue({ isByoUser: true });
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: '1024' });

      const result = await service.getQuota(testUserId);

      expect(result.advisory).toBe(true);
    });

    it('should return advisory: false for non-BYO users', async () => {
      mockVaultRepo.findOne.mockResolvedValue({ isByoUser: false });
      mockQueryBuilder.getRawOne.mockResolvedValue({ total: '1024' });

      const result = await service.getQuota(testUserId);

      expect(result.advisory).toBe(false);
    });
  });

  describe('guardedUnpin', () => {
    const testCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockPinnedRow = { userId: testUserId, cid: testCid };

    it('no-row, CID unknown: resolves without touching Kubo, quota, or cross-user counter', async () => {
      mockManagerPinnedCidRepo.findOne.mockResolvedValue(null);

      await expect(service.guardedUnpin(testUserId, testCid)).resolves.toBeUndefined();

      expect(mockManagerPinnedCidRepo.delete).not.toHaveBeenCalled();
      expect(mockManagerPendingUnpinRepo.createQueryBuilder).not.toHaveBeenCalled();
      expect(mockIpfsProvider.unpinFile).not.toHaveBeenCalled();
      expect(mockMetricsService.unpinCrossUserAttempts.inc).not.toHaveBeenCalled();
      // IN-01: no row deleted — metric must NOT fire on no-op paths
      expect(mockMetricsService.fileUnpins.inc).not.toHaveBeenCalled();
    });

    it('no-row, cross-user: calls unpinCrossUserAttempts.inc and logger.warn, no delete, no Kubo', async () => {
      // own row: null; any-user row: has a row (cross-user)
      mockManagerPinnedCidRepo.findOne
        .mockResolvedValueOnce(null) // own findOne (userId + cid)
        .mockResolvedValueOnce({ userId: 'otherUser', cid: testCid }); // any-user findOne (cid only)

      await expect(service.guardedUnpin(testUserId, testCid)).resolves.toBeUndefined();

      expect(mockMetricsService.unpinCrossUserAttempts.inc).toHaveBeenCalledTimes(1);
      expect(mockManagerPinnedCidRepo.delete).not.toHaveBeenCalled();
      expect(mockIpfsProvider.unpinFile).not.toHaveBeenCalled();
      // IN-01: no row deleted — metric must NOT fire on cross-user no-op paths
      expect(mockMetricsService.fileUnpins.inc).not.toHaveBeenCalled();
    });

    it('no-row, cross-user, suppressCrossUserAudit: does NOT increment counter (internal rollback)', async () => {
      // own row: null; any-user row: present (would normally count as cross-user)
      mockManagerPinnedCidRepo.findOne
        .mockResolvedValueOnce(null) // own findOne (userId + cid)
        .mockResolvedValueOnce({ userId: 'otherUser', cid: testCid }); // any-user findOne (cid only)

      await expect(
        service.guardedUnpin(testUserId, testCid, { suppressCrossUserAudit: true })
      ).resolves.toBeUndefined();

      expect(mockMetricsService.unpinCrossUserAttempts.inc).not.toHaveBeenCalled();
      expect(mockManagerPinnedCidRepo.delete).not.toHaveBeenCalled();
      expect(mockIpfsProvider.unpinFile).not.toHaveBeenCalled();
    });

    it('owned, refcount > 0: deletes caller row but does NOT insert outbox row or call Kubo', async () => {
      mockManagerPinnedCidRepo.findOne.mockResolvedValue(mockPinnedRow);
      mockManagerQueryBuilder.getRawOne.mockResolvedValue({ count: '1' });

      await expect(service.guardedUnpin(testUserId, testCid)).resolves.toBeUndefined();

      expect(mockManagerPinnedCidRepo.delete).toHaveBeenCalledWith({
        userId: testUserId,
        cid: testCid,
      });
      expect(mockManagerQueryBuilder.execute).not.toHaveBeenCalled();
      expect(mockIpfsProvider.unpinFile).not.toHaveBeenCalled();
      // IN-01: row was deleted → metric fires even when refcount > 0 (caller's row removed)
      expect(mockMetricsService.fileUnpins.inc).toHaveBeenCalledTimes(1);
    });

    it('owned, refcount === 0: inserts outbox row inside transaction, then calls Kubo and deletes outbox row post-commit', async () => {
      mockManagerPinnedCidRepo.findOne.mockResolvedValue(mockPinnedRow);
      mockManagerQueryBuilder.getRawOne.mockResolvedValue({ count: '0' });
      mockIpfsProvider.unpinFile.mockResolvedValue(undefined);

      await expect(service.guardedUnpin(testUserId, testCid)).resolves.toBeUndefined();

      expect(mockManagerPinnedCidRepo.delete).toHaveBeenCalledWith({
        userId: testUserId,
        cid: testCid,
      });
      expect(mockManagerQueryBuilder.orIgnore).toHaveBeenCalled();
      expect(mockManagerQueryBuilder.execute).toHaveBeenCalled();
      expect(mockIpfsProvider.unpinFile).toHaveBeenCalledWith(testCid);
      expect(mockPendingUnpinRepository.delete).toHaveBeenCalledWith({ cid: testCid });
      // IN-01: row was deleted → metric fires
      expect(mockMetricsService.fileUnpins.inc).toHaveBeenCalledTimes(1);
    });

    it('owned, refcount === 0, Kubo throws: guardedUnpin still resolves, outbox row left (for worker)', async () => {
      mockManagerPinnedCidRepo.findOne.mockResolvedValue(mockPinnedRow);
      mockManagerQueryBuilder.getRawOne.mockResolvedValue({ count: '0' });
      mockIpfsProvider.unpinFile.mockRejectedValue(new Error('Kubo unavailable'));

      await expect(service.guardedUnpin(testUserId, testCid)).resolves.toBeUndefined();

      expect(mockIpfsProvider.unpinFile).toHaveBeenCalledWith(testCid);
      expect(mockPendingUnpinRepository.delete).not.toHaveBeenCalled();
      // IN-01: row was deleted → metric fires even when Kubo fails
      expect(mockMetricsService.fileUnpins.inc).toHaveBeenCalledTimes(1);
    });

    it('WR-01: advisory lock query must not use abs(int4) form (INT_MIN CID stays deletable)', async () => {
      // Regression for D-01 / WR-01: abs(int4) overflows for INT_MIN (-2147483648),
      // making the file permanently undeletable. The fix: pg_advisory_xact_lock(hashtext($1)::bigint)
      // without abs() — signed bigint sign-extends safely from int4.
      mockManagerPinnedCidRepo.findOne.mockResolvedValue(mockPinnedRow);
      mockManagerQueryBuilder.getRawOne.mockResolvedValue({ count: '0' });
      mockIpfsProvider.unpinFile.mockResolvedValue(undefined);

      let capturedSql = '';
      mockManager.query.mockImplementation((sql: string) => {
        capturedSql = sql;
        return Promise.resolve([]);
      });

      await service.guardedUnpin(testUserId, testCid);

      expect(capturedSql).toMatch(/pg_advisory_xact_lock/);
      expect(capturedSql).not.toMatch(/abs\(hashtext/);
    });

    it('advisory lock ordering: pg_advisory_xact_lock is called via manager.query BEFORE pinnedCidRepo.delete', async () => {
      mockManagerPinnedCidRepo.findOne.mockResolvedValue(mockPinnedRow);
      mockManagerQueryBuilder.getRawOne.mockResolvedValue({ count: '1' });

      const callOrder: string[] = [];
      mockManager.query.mockImplementation((sql: string) => {
        // The lock now computes its key inline, so the SQL contains both
        // 'pg_advisory_xact_lock' and 'hashtext' — match the lock first.
        if (sql.includes('pg_advisory_xact_lock')) {
          callOrder.push('advisory_lock');
          return Promise.resolve([]);
        }
        if (sql.includes('hashtext')) {
          callOrder.push('hashtext');
          return Promise.resolve([{ h: '123456789' }]);
        }
        return Promise.resolve([]);
      });
      mockManagerPinnedCidRepo.delete.mockImplementation(() => {
        callOrder.push('delete');
        return Promise.resolve({ affected: 1 });
      });

      await service.guardedUnpin(testUserId, testCid);

      const lockIdx = callOrder.indexOf('advisory_lock');
      const deleteIdx = callOrder.indexOf('delete');
      expect(lockIdx).toBeGreaterThanOrEqual(0);
      expect(deleteIdx).toBeGreaterThan(lockIdx);
    });
  });
});
