import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Job } from 'bullmq';
import { MigrationProcessor } from './migration.processor';
import { PinMigration } from './migration.entity';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { MigrationService } from './migration.service';
import { User } from '../auth/entities/user.entity';

// Mock global fetch
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('MigrationProcessor', () => {
  let processor: MigrationProcessor;
  let mockMigrationRepo: {
    findOneOrFail: jest.Mock;
    update: jest.Mock;
  };
  let mockPinnedCidRepo: {
    find: jest.Mock;
  };
  let mockMigrationService: {
    updateProgress: jest.Mock;
  };
  let mockConfigService: {
    get: jest.Mock;
  };

  const testMigrationId = '660e8400-e29b-41d4-a716-446655440001';
  const testUserId = '550e8400-e29b-41d4-a716-446655440000';

  const baseMigration: PinMigration = {
    id: testMigrationId,
    userId: testUserId,
    status: 'pending',
    totalCids: 5,
    migratedCids: 0,
    failedCids: 0,
    sourceConfigEncrypted: 'encrypted-source',
    destConfigEncrypted: 'encrypted-dest',
    failedCidList: null,
    createdAt: new Date('2026-03-24T12:00:00.000Z'),
    updatedAt: new Date('2026-03-24T12:00:00.000Z'),
    completedAt: null,
  };

  const makeJob = (migrationId: string): Job<{ migrationId: string }> =>
    ({ data: { migrationId } }) as unknown as Job<{ migrationId: string }>;

  const makePinnedCids = (count: number): PinnedCid[] =>
    Array.from({ length: count }, (_, i) => ({
      id: `cid-uuid-${i}`,
      userId: testUserId,
      cid: `bafkrei${i}`,
      sizeBytes: '1024',
      pinnedAt: new Date(),
      user: {} as User,
    }));

  beforeEach(async () => {
    mockMigrationRepo = {
      findOneOrFail: jest.fn(),
      update: jest.fn(),
    };

    mockPinnedCidRepo = {
      find: jest.fn(),
    };

    mockMigrationService = {
      updateProgress: jest.fn(),
    };

    mockConfigService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MigrationProcessor,
        {
          provide: getRepositoryToken(PinMigration),
          useValue: mockMigrationRepo,
        },
        {
          provide: getRepositoryToken(PinnedCid),
          useValue: mockPinnedCidRepo,
        },
        {
          provide: MigrationService,
          useValue: mockMigrationService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    processor = module.get<MigrationProcessor>(MigrationProcessor);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('process', () => {
    it('should transition pending migration to running', async () => {
      const migration = { ...baseMigration, status: 'pending' as const };
      // First call: initial load, Second call: batch check, Third call: final check
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce({ ...migration, status: 'running' })
        .mockResolvedValueOnce({ ...migration, status: 'running' });

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(2));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: ['bafkrei0', 'bafkrei1'], failed: [] }),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockMigrationRepo.update).toHaveBeenCalledWith(testMigrationId, {
        status: 'running',
      });
    });

    it('should NOT transition to running if already running', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(1));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: ['bafkrei0'], failed: [] }),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      // Should only be called for the 'completed' update at the end, not for 'running'
      const runningCalls = mockMigrationRepo.update.mock.calls.filter(
        (call) => call[1].status === 'running'
      );
      expect(runningCalls).toHaveLength(0);
    });

    it('should fail if TEE_WORKER_URL is not configured', async () => {
      const migration = { ...baseMigration, status: 'pending' as const };
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce(migration);
      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(1));
      mockConfigService.get.mockReturnValue(undefined);
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockMigrationRepo.update).toHaveBeenCalledWith(testMigrationId, {
        status: 'failed',
      });
    });

    it('should fail if TEE_WORKER_SECRET is not configured', async () => {
      const migration = { ...baseMigration, status: 'pending' as const };
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce(migration);
      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(1));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce(undefined);
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockMigrationRepo.update).toHaveBeenCalledWith(testMigrationId, {
        status: 'failed',
      });
    });

    it('should stop processing when migration is paused between batches', async () => {
      const migration = { ...baseMigration, status: 'pending' as const };
      // Initial load: pending
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(15)); // More than BATCH_SIZE=10
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      // First batch check: running (process batch)
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce({
        ...migration,
        status: 'running',
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: Array(10).fill('cid'), failed: [] }),
      });

      // Second batch check: paused (should stop)
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce({
        ...migration,
        status: 'paused',
      });

      // Final status check: paused (should NOT mark completed)
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce({
        ...migration,
        status: 'paused',
      });

      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      // Should have made only 1 fetch call (first batch), not 2
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Should NOT mark as completed since it was paused
      const completedCalls = mockMigrationRepo.update.mock.calls.filter(
        (call) => call[1].status === 'completed'
      );
      expect(completedCalls).toHaveLength(0);
    });

    it('should stop processing when migration is cancelled between batches', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(15));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      // First batch check: running
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce(migration);
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: Array(10).fill('cid'), failed: [] }),
      });

      // Second batch check: cancelled
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce({
        ...migration,
        status: 'cancelled',
      });

      // Final check: cancelled
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce({
        ...migration,
        status: 'cancelled',
      });

      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockFetch).toHaveBeenCalledTimes(1);

      const completedCalls = mockMigrationRepo.update.mock.calls.filter(
        (call) => call[1].status === 'completed'
      );
      expect(completedCalls).toHaveLength(0);
    });

    it('should process CIDs in batches of 10 and update progress', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      // Initial load
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce(migration);

      const pinnedCids = makePinnedCids(12); // 2 batches: 10 + 2
      mockPinnedCidRepo.find.mockResolvedValue(pinnedCids);
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      // Batch checks: both running
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      // Two successful batches
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            succeeded: pinnedCids.slice(0, 10).map((p) => p.cid),
            failed: [],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            succeeded: pinnedCids.slice(10).map((p) => p.cid),
            failed: [],
          }),
        });

      // Final status check: running
      mockMigrationRepo.findOneOrFail.mockResolvedValueOnce(migration);
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(mockMigrationService.updateProgress).toHaveBeenCalledTimes(2);

      // First batch: 10 succeeded
      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(testMigrationId, 10, 0, []);
      // Second batch: 2 succeeded
      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(testMigrationId, 2, 0, []);
    });

    it('should send correct payload to TEE', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(2));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: ['bafkrei0', 'bafkrei1'], failed: [] }),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockFetch).toHaveBeenCalledWith(
        'https://tee.example.com/migrate',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer secret-token',
          },
          body: JSON.stringify({
            cids: ['bafkrei0', 'bafkrei1'],
            sourceConfigEncrypted: 'encrypted-source',
            destConfigEncrypted: 'encrypted-dest',
          }),
        })
      );
    });

    it('should use a 300s batch timeout exceeding worst-case TEE batch duration (~130s)', async () => {
      const timeoutSpy = jest.spyOn(AbortSignal, 'timeout');

      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(1));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: ['bafkrei0'], failed: [] }),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(timeoutSpy).toHaveBeenCalledWith(300_000);

      timeoutSpy.mockRestore();
    });

    it('should pause migration on TEE 401 auth failure', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(3));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => 'Unauthorized',
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      // Should update progress with all CIDs as failed
      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(testMigrationId, 0, 3, [
        'bafkrei0',
        'bafkrei1',
        'bafkrei2',
      ]);

      // Should pause the migration
      expect(mockMigrationRepo.update).toHaveBeenCalledWith(testMigrationId, {
        status: 'paused',
      });

      // Should return early — no completed update
      const completedCalls = mockMigrationRepo.update.mock.calls.filter(
        (call) => call[1].status === 'completed'
      );
      expect(completedCalls).toHaveLength(0);
    });

    it('should handle non-401 TEE error by recording failures and continuing', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(3));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: async () => 'Internal Server Error',
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      // The non-401 error throws, caught by catch block -> updateProgress with all as failed
      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(testMigrationId, 0, 3, [
        'bafkrei0',
        'bafkrei1',
        'bafkrei2',
      ]);
    });

    it('should handle fetch network error via catch block', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(2));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockRejectedValue(new Error('Network error'));
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      // Catch block records all CIDs in batch as failed
      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(testMigrationId, 0, 2, [
        'bafkrei0',
        'bafkrei1',
      ]);
    });

    it('should handle non-Error thrown in catch block', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(1));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      // Reject with a non-Error value to hit String(err) branch
      mockFetch.mockRejectedValue('string error');
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(testMigrationId, 0, 1, [
        'bafkrei0',
      ]);
    });

    it('should mark migration as completed when all batches finish and status is running', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration); // final check: still running

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(3));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: ['bafkrei0', 'bafkrei1', 'bafkrei2'], failed: [] }),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockMigrationRepo.update).toHaveBeenCalledWith(
        testMigrationId,
        expect.objectContaining({
          status: 'completed',
          completedAt: expect.any(Date),
        })
      );
    });

    it('should NOT mark completed when final status is not running', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce({ ...migration, status: 'paused' }); // final check: paused

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(2));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ succeeded: ['bafkrei0', 'bafkrei1'], failed: [] }),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      const completedCalls = mockMigrationRepo.update.mock.calls.filter(
        (call) => call[1].status === 'completed'
      );
      expect(completedCalls).toHaveLength(0);
    });

    it('should handle zero CIDs gracefully', async () => {
      const migration = { ...baseMigration, status: 'pending' as const };
      // Initial + final
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce({ ...migration, status: 'running' });

      mockPinnedCidRepo.find.mockResolvedValue([]);
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      // No fetch calls for empty CID list
      expect(mockFetch).not.toHaveBeenCalled();

      // Should mark completed since status is running
      expect(mockMigrationRepo.update).toHaveBeenCalledWith(
        testMigrationId,
        expect.objectContaining({
          status: 'completed',
        })
      );
    });

    it('should handle partial success in batch response', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(3));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          succeeded: ['bafkrei0'],
          failed: ['bafkrei1', 'bafkrei2'],
        }),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(testMigrationId, 1, 2, [
        'bafkrei1',
        'bafkrei2',
      ]);
    });

    it('should handle response with undefined succeeded/failed arrays', async () => {
      const migration = { ...baseMigration, status: 'running' as const };
      mockMigrationRepo.findOneOrFail
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration)
        .mockResolvedValueOnce(migration);

      mockPinnedCidRepo.find.mockResolvedValue(makePinnedCids(2));
      mockConfigService.get
        .mockReturnValueOnce('https://tee.example.com')
        .mockReturnValueOnce('secret-token');

      // Response with neither succeeded nor failed
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({}),
      });
      mockMigrationRepo.update.mockResolvedValue({ affected: 1 });

      await processor.process(makeJob(testMigrationId));

      // Uses nullish coalescing: succeeded?.length ?? 0 = 0, failed?.length ?? 0 = 0
      expect(mockMigrationService.updateProgress).toHaveBeenCalledWith(
        testMigrationId,
        0,
        0,
        undefined
      );
    });
  });
});
