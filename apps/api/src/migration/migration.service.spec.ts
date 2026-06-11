import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { getQueueToken } from '@nestjs/bullmq';
import { ConflictException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { MigrationService } from './migration.service';
import { PinMigration } from './migration.entity';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';

describe('MigrationService', () => {
  let service: MigrationService;
  let mockMigrationRepo: {
    findOne: jest.Mock;
    findOneOrFail: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    update: jest.Mock;
  };
  let mockPinnedCidRepo: {
    count: jest.Mock;
  };
  let mockQueue: {
    add: jest.Mock;
  };

  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testMigrationId = '660e8400-e29b-41d4-a716-446655440001';

  const testDto = {
    sourceConfigEncrypted: 'encrypted-source-config',
    destConfigEncrypted: 'encrypted-dest-config',
  };

  const mockMigrationEntity: PinMigration = {
    id: testMigrationId,
    userId: testUserId,
    status: 'pending',
    totalCids: 5,
    migratedCids: 0,
    failedCids: 0,
    sourceConfigEncrypted: testDto.sourceConfigEncrypted,
    destConfigEncrypted: testDto.destConfigEncrypted,
    failedCidList: null,
    createdAt: new Date('2026-03-24T12:00:00.000Z'),
    updatedAt: new Date('2026-03-24T12:00:00.000Z'),
    completedAt: null,
  };

  beforeEach(async () => {
    mockMigrationRepo = {
      findOne: jest.fn(),
      findOneOrFail: jest.fn(),
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
    };

    mockPinnedCidRepo = {
      count: jest.fn(),
    };

    mockQueue = {
      add: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MigrationService,
        {
          provide: getRepositoryToken(PinMigration),
          useValue: mockMigrationRepo,
        },
        {
          provide: getRepositoryToken(PinnedCid),
          useValue: mockPinnedCidRepo,
        },
        {
          provide: getQueueToken('pin-migration'),
          useValue: mockQueue,
        },
      ],
    }).compile();

    service = module.get<MigrationService>(MigrationService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('startMigration', () => {
    it('should create PinMigration entity with correct totalCids count and return migration ID', async () => {
      // No active migration exists
      mockMigrationRepo.findOne.mockResolvedValue(null);

      // 5 pinned CIDs for this user
      const pinnedCids = Array.from({ length: 5 }, (_, i) => ({
        id: `cid-${i}`,
        userId: testUserId,
        cid: `bafkrei${i}`,
        sizeBytes: '1024',
        pinnedAt: new Date(),
      }));
      mockPinnedCidRepo.count.mockResolvedValue(pinnedCids.length);

      mockMigrationRepo.create.mockReturnValue(mockMigrationEntity);
      mockMigrationRepo.save.mockResolvedValue(mockMigrationEntity);
      mockQueue.add.mockResolvedValue({ id: 'job-1' });

      const result = await service.startMigration(testUserId, testDto);

      expect(result).toBe(testMigrationId);
      expect(mockMigrationRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: testUserId,
          status: 'pending',
          totalCids: 5,
          migratedCids: 0,
          failedCids: 0,
          sourceConfigEncrypted: testDto.sourceConfigEncrypted,
          destConfigEncrypted: testDto.destConfigEncrypted,
        })
      );
      expect(mockMigrationRepo.save).toHaveBeenCalled();
    });

    it('should count pinned CIDs for the user from PinnedCid repository', async () => {
      mockMigrationRepo.findOne.mockResolvedValue(null);

      const pinnedCids = Array.from({ length: 3 }, (_, i) => ({
        id: `cid-${i}`,
        userId: testUserId,
        cid: `bafkrei${i}`,
        sizeBytes: '2048',
        pinnedAt: new Date(),
      }));
      mockPinnedCidRepo.count.mockResolvedValue(pinnedCids.length);

      mockMigrationRepo.create.mockReturnValue({ ...mockMigrationEntity, totalCids: 3 });
      mockMigrationRepo.save.mockResolvedValue({ ...mockMigrationEntity, totalCids: 3 });
      mockQueue.add.mockResolvedValue({ id: 'job-1' });

      await service.startMigration(testUserId, testDto);

      expect(mockPinnedCidRepo.count).toHaveBeenCalledWith({
        where: { userId: testUserId },
      });
      expect(mockMigrationRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ totalCids: 3 })
      );
    });

    it('should add BullMQ job with migration ID', async () => {
      mockMigrationRepo.findOne.mockResolvedValue(null);
      mockPinnedCidRepo.count.mockResolvedValue(0);
      mockMigrationRepo.create.mockReturnValue({ ...mockMigrationEntity, totalCids: 0 });
      mockMigrationRepo.save.mockResolvedValue(mockMigrationEntity);
      mockQueue.add.mockResolvedValue({ id: 'job-1' });

      await service.startMigration(testUserId, testDto);

      expect(mockQueue.add).toHaveBeenCalledWith('pin-migration', {
        migrationId: testMigrationId,
      });
    });

    it('should throw ConflictException if active migration exists', async () => {
      mockMigrationRepo.findOne.mockResolvedValue(mockMigrationEntity);

      await expect(service.startMigration(testUserId, testDto)).rejects.toThrow(ConflictException);
    });
  });

  describe('getStatus', () => {
    it('should return latest migration for user as MigrationStatusDto', async () => {
      mockMigrationRepo.findOne.mockResolvedValue(mockMigrationEntity);

      const result = await service.getStatus(testUserId);

      expect(result).toEqual({
        id: testMigrationId,
        status: 'pending',
        totalCids: 5,
        migratedCids: 0,
        failedCids: 0,
        createdAt: mockMigrationEntity.createdAt.toISOString(),
        completedAt: null,
      });
      expect(mockMigrationRepo.findOne).toHaveBeenCalledWith({
        where: { userId: testUserId },
        order: { createdAt: 'DESC' },
      });
    });

    it('should return null when no migration exists for user', async () => {
      mockMigrationRepo.findOne.mockResolvedValue(null);

      const result = await service.getStatus(testUserId);

      expect(result).toBeNull();
    });
  });

  describe('pauseMigration', () => {
    it('should set status to paused for the correct user and migration ID', async () => {
      const runningMigration = { ...mockMigrationEntity, status: 'running' as const };
      mockMigrationRepo.findOne.mockResolvedValue(runningMigration);
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await service.pauseMigration(testUserId, testMigrationId);

      expect(mockMigrationRepo.update).toHaveBeenCalledWith(testMigrationId, {
        status: 'paused',
      });
    });

    it('should throw ConflictException when migration is not running or pending', async () => {
      const completedMigration = { ...mockMigrationEntity, status: 'completed' as const };
      mockMigrationRepo.findOne.mockResolvedValue(completedMigration);

      await expect(service.pauseMigration(testUserId, testMigrationId)).rejects.toThrow(
        ConflictException
      );
    });

    it('should throw NotFoundException when migration not found', async () => {
      mockMigrationRepo.findOne.mockResolvedValue(null);

      await expect(service.pauseMigration(testUserId, testMigrationId)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should throw ForbiddenException when migration belongs to another user', async () => {
      const otherUserMigration = {
        ...mockMigrationEntity,
        userId: 'other-user-id',
        status: 'running' as const,
      };
      mockMigrationRepo.findOne.mockResolvedValue(otherUserMigration);

      await expect(service.pauseMigration(testUserId, testMigrationId)).rejects.toThrow(
        ForbiddenException
      );
    });
  });

  describe('resumeMigration', () => {
    it('should set status to running', async () => {
      const pausedMigration = { ...mockMigrationEntity, status: 'paused' as const };
      mockMigrationRepo.findOne.mockResolvedValue(pausedMigration);
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });
      mockQueue.add.mockResolvedValue({ id: 'job-2' });

      await service.resumeMigration(testUserId, testMigrationId);

      expect(mockMigrationRepo.update).toHaveBeenCalledWith(testMigrationId, {
        status: 'running',
      });
      expect(mockQueue.add).toHaveBeenCalledWith('pin-migration', {
        migrationId: testMigrationId,
      });
    });

    it('should throw ConflictException when migration is not paused', async () => {
      const runningMigration = { ...mockMigrationEntity, status: 'running' as const };
      mockMigrationRepo.findOne.mockResolvedValue(runningMigration);

      await expect(service.resumeMigration(testUserId, testMigrationId)).rejects.toThrow(
        ConflictException
      );
    });
  });

  describe('cancelMigration', () => {
    it('should set status to cancelled', async () => {
      const runningMigration = { ...mockMigrationEntity, status: 'running' as const };
      mockMigrationRepo.findOne.mockResolvedValue(runningMigration);
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await service.cancelMigration(testUserId, testMigrationId);

      expect(mockMigrationRepo.update).toHaveBeenCalledWith(testMigrationId, {
        status: 'cancelled',
      });
    });

    it('should throw ConflictException when migration is already completed', async () => {
      const completedMigration = { ...mockMigrationEntity, status: 'completed' as const };
      mockMigrationRepo.findOne.mockResolvedValue(completedMigration);

      await expect(service.cancelMigration(testUserId, testMigrationId)).rejects.toThrow(
        ConflictException
      );
    });
  });

  describe('updateProgress', () => {
    it('should increment migratedCids and failedCids counters', async () => {
      const migration = { ...mockMigrationEntity, totalCids: 10, migratedCids: 2, failedCids: 1 };
      mockMigrationRepo.findOneOrFail.mockResolvedValue(migration);
      mockMigrationRepo.save.mockResolvedValue(migration);

      await service.updateProgress(testMigrationId, 3, 1);

      expect(mockMigrationRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          migratedCids: 5,
          failedCids: 2,
        })
      );
    });

    it('should append failed CIDs to failedCidList', async () => {
      const migration = {
        ...mockMigrationEntity,
        migratedCids: 0,
        failedCids: 0,
        failedCidList: null,
      };
      mockMigrationRepo.findOneOrFail.mockResolvedValue(migration);
      mockMigrationRepo.save.mockResolvedValue(migration);

      await service.updateProgress(testMigrationId, 0, 2, ['bafkrei1', 'bafkrei2']);

      expect(mockMigrationRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          failedCidList: 'bafkrei1,bafkrei2',
        })
      );
    });

    it('should append to existing failedCidList', async () => {
      const migration = {
        ...mockMigrationEntity,
        migratedCids: 0,
        failedCids: 1,
        failedCidList: 'bafkrei0',
      };
      mockMigrationRepo.findOneOrFail.mockResolvedValue(migration);
      mockMigrationRepo.save.mockResolvedValue(migration);

      await service.updateProgress(testMigrationId, 0, 1, ['bafkrei1']);

      expect(mockMigrationRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          failedCidList: 'bafkrei0,bafkrei1',
        })
      );
    });

    it('should dedupe failedCidList and derive failedCids from the deduped list', async () => {
      // bafkrei0 already recorded as failed; the same batch is re-reported
      // (e.g. HTTP timeout abort followed by a retry of the same batch).
      const migration = {
        ...mockMigrationEntity,
        totalCids: 5,
        migratedCids: 0,
        failedCids: 1,
        failedCidList: 'bafkrei0',
      };
      mockMigrationRepo.findOneOrFail.mockResolvedValue(migration);
      mockMigrationRepo.save.mockResolvedValue(migration);

      await service.updateProgress(testMigrationId, 0, 2, ['bafkrei0', 'bafkrei1']);

      expect(mockMigrationRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          failedCidList: 'bafkrei0,bafkrei1',
          failedCids: 2, // deduped list length, NOT 1 + 2 = 3
        })
      );
    });

    it('should clamp migratedCids so migrated + failed never exceeds totalCids', async () => {
      // Double-reported batch: a 5-CID batch timed out (counted as 5 failed),
      // then the TEE worker actually completed it and reports 5 migrated.
      const migration = {
        ...mockMigrationEntity,
        totalCids: 5,
        migratedCids: 3,
        failedCids: 5,
        failedCidList: 'bafkrei0,bafkrei1,bafkrei2,bafkrei3,bafkrei4',
      };
      mockMigrationRepo.findOneOrFail.mockResolvedValue(migration);
      mockMigrationRepo.save.mockResolvedValue(migration);

      await service.updateProgress(testMigrationId, 5, 0);

      expect(mockMigrationRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          // migratedCids capped at totalCids - failedCids = 0, not 3 + 5 = 8
          migratedCids: 0,
          failedCids: 5,
        })
      );
      const saved = mockMigrationRepo.save.mock.calls[0][0];
      expect(saved.migratedCids + saved.failedCids).toBeLessThanOrEqual(saved.totalCids);
    });

    it('should keep totals within totalCids when duplicate failed reports arrive', async () => {
      // All 3 CIDs already failed once; the identical failure report arrives again.
      const migration = {
        ...mockMigrationEntity,
        totalCids: 3,
        migratedCids: 0,
        failedCids: 3,
        failedCidList: 'bafkrei0,bafkrei1,bafkrei2',
      };
      mockMigrationRepo.findOneOrFail.mockResolvedValue(migration);
      mockMigrationRepo.save.mockResolvedValue(migration);

      await service.updateProgress(testMigrationId, 0, 3, ['bafkrei0', 'bafkrei1', 'bafkrei2']);

      expect(mockMigrationRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          migratedCids: 0,
          failedCids: 3, // unchanged — duplicates deduped
          failedCidList: 'bafkrei0,bafkrei1,bafkrei2',
        })
      );
    });
  });
});
