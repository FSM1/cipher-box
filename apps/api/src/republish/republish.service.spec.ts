import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { RepublishService } from './republish.service';
import { IpnsRepublishSchedule } from './republish-schedule.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { TeeService, RepublishResult } from '../tee/tee.service';
import { TeeKeyStateService } from '../tee/tee-key-state.service';

// atob is not available in all Node.js test environments
global.atob = (str: string) => Buffer.from(str, 'base64').toString('binary');

describe('RepublishService', () => {
  let service: RepublishService;
  let scheduleRepository: jest.Mocked<Record<string, jest.Mock>>;
  let folderIpnsRepository: jest.Mocked<Record<string, jest.Mock>>;
  let teeService: jest.Mocked<Partial<TeeService>>;
  let teeKeyStateService: jest.Mocked<Partial<TeeKeyStateService>>;
  let fetchMock: jest.Mock;

  // Make delay() resolve instantly
  let setTimeoutSpy: jest.SpyInstance;

  const DELEGATED_ROUTING_URL = 'https://delegated-ipfs.dev';

  function createMockEntry(overrides: Partial<IpnsRepublishSchedule> = {}): IpnsRepublishSchedule {
    return {
      id: 'entry-uuid-1',
      userId: 'user-uuid-1',
      ipnsName: 'k51test123',
      encryptedIpnsKey: Buffer.from('encrypted-data'),
      keyEpoch: 1,
      latestCid: 'bafkrei123',
      sequenceNumber: '5',
      nextRepublishAt: new Date('2026-01-01'),
      lastRepublishAt: null,
      consecutiveFailures: 0,
      status: 'active',
      lastError: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    } as IpnsRepublishSchedule;
  }

  function createMockTeeState(overrides: Record<string, unknown> = {}) {
    return {
      id: 'state-uuid-1',
      currentEpoch: 2,
      currentPublicKey: Buffer.from('04' + 'ab'.repeat(64), 'hex'),
      previousEpoch: 1,
      previousPublicKey: Buffer.from('04' + 'cd'.repeat(64), 'hex'),
      gracePeriodEndsAt: new Date('2026-03-01'),
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    };
  }

  beforeEach(async () => {
    fetchMock = jest.fn();
    global.fetch = fetchMock;

    setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation((cb: () => void) => {
      cb();
      return 0 as unknown as NodeJS.Timeout;
    });

    const mockScheduleRepo = {
      find: jest.fn(),
      findOne: jest.fn(),
      save: jest.fn(),
      create: jest.fn(),
      count: jest.fn(),
      update: jest.fn(),
    };

    const mockFolderIpnsRepo = {
      update: jest.fn(),
    };

    const mockTeeService = {
      republish: jest.fn(),
      getHealth: jest.fn(),
    };

    const mockTeeKeyStateService = {
      getCurrentState: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn((key: string, defaultValue?: string) => {
        const config: Record<string, string> = {
          DELEGATED_ROUTING_URL: DELEGATED_ROUTING_URL,
        };
        return config[key] ?? defaultValue;
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RepublishService,
        { provide: getRepositoryToken(IpnsRepublishSchedule), useValue: mockScheduleRepo },
        { provide: getRepositoryToken(FolderIpns), useValue: mockFolderIpnsRepo },
        { provide: TeeService, useValue: mockTeeService },
        { provide: TeeKeyStateService, useValue: mockTeeKeyStateService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<RepublishService>(RepublishService);
    scheduleRepository = module.get(getRepositoryToken(IpnsRepublishSchedule));
    folderIpnsRepository = module.get(getRepositoryToken(FolderIpns));
    teeService = module.get(TeeService);
    teeKeyStateService = module.get(TeeKeyStateService);
  });

  afterEach(() => {
    jest.clearAllMocks();
    setTimeoutSpy.mockRestore();
  });

  // ---------------------------------------------------------------------------
  // Helper to create a mock fetch Response
  // ---------------------------------------------------------------------------
  function mockResponse(status = 200, headers: Record<string, string> = {}): Response {
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: {
        get: jest.fn((key: string) => headers[key] || null),
      },
    } as unknown as Response;
  }

  // ===========================================================================
  // getDueEntries()
  // ===========================================================================
  describe('getDueEntries', () => {
    it('should return entries with active or retrying status that are due', async () => {
      const entries = [
        createMockEntry(),
        createMockEntry({ id: 'entry-uuid-2', ipnsName: 'k51test456' }),
      ];
      scheduleRepository.find.mockResolvedValue(entries);

      const result = await service.getDueEntries();

      expect(result).toEqual(entries);
      expect(result).toHaveLength(2);
      expect(scheduleRepository.find).toHaveBeenCalledWith(
        expect.objectContaining({
          order: { nextRepublishAt: 'ASC' },
          take: 500,
        })
      );
    });

    it('should return empty array when no entries are due', async () => {
      scheduleRepository.find.mockResolvedValue([]);

      const result = await service.getDueEntries();

      expect(result).toEqual([]);
    });
  });

  // ===========================================================================
  // processRepublishBatch()
  // ===========================================================================
  describe('processRepublishBatch', () => {
    it('should return zeros when no entries are due', async () => {
      scheduleRepository.find.mockResolvedValue([]);

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 0, succeeded: 0, failed: 0 });
      expect(teeService.republish).not.toHaveBeenCalled();
    });

    it('should return all-failed when TEE key state is not initialized', async () => {
      const entries = [createMockEntry(), createMockEntry({ id: 'entry-uuid-2' })];
      scheduleRepository.find.mockResolvedValue(entries);
      teeKeyStateService.getCurrentState!.mockResolvedValue(null);

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 2, succeeded: 0, failed: 2 });
      expect(teeService.republish).not.toHaveBeenCalled();
    });

    it('should process a successful batch with republish and publish', async () => {
      const entry = createMockEntry();
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('signed-record-bytes').toString('base64'),
        newSequenceNumber: '6',
      };
      teeService.republish!.mockResolvedValue([teeResult]);

      // publishSignedRecord -- mock successful fetch
      fetchMock.mockResolvedValue(mockResponse(200));

      // scheduleRepository.save on success
      scheduleRepository.save.mockResolvedValue(entry);
      folderIpnsRepository.update.mockResolvedValue({ affected: 1 });

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 1, failed: 0 });
      expect(teeService.republish).toHaveBeenCalledWith([
        expect.objectContaining({
          encryptedIpnsKey: entry.encryptedIpnsKey.toString('base64'),
          keyEpoch: 1,
          ipnsName: 'k51test123',
          latestCid: 'bafkrei123',
          sequenceNumber: '5',
          currentEpoch: 2,
          previousEpoch: 1,
        }),
      ]);
      // Verify entry was updated on success
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          sequenceNumber: '6',
          consecutiveFailures: 0,
          status: 'active',
          lastError: null,
        })
      );
      // Verify FolderIpns sync
      expect(folderIpnsRepository.update).toHaveBeenCalledWith(
        { userId: 'user-uuid-1', ipnsName: 'k51test123' },
        { sequenceNumber: '6' }
      );
    });

    it('should handle TEE unreachable (teeService.republish throws)', async () => {
      const entries = [
        createMockEntry(),
        createMockEntry({ id: 'entry-uuid-2', ipnsName: 'k51test456' }),
      ];
      scheduleRepository.find.mockResolvedValue(entries);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      teeService.republish!.mockRejectedValue(new Error('Connection refused'));
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 2, succeeded: 0, failed: 2 });
      // Both entries should have handleEntryFailure called
      expect(scheduleRepository.save).toHaveBeenCalledTimes(2);
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          consecutiveFailures: 1,
          status: 'retrying',
          lastError: expect.stringContaining('TEE unreachable'),
        })
      );
    });

    it('should handle TEE signing failure (result.success = false)', async () => {
      const entry = createMockEntry();
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Decryption failed: wrong epoch',
      };
      teeService.republish!.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 0, failed: 1 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          consecutiveFailures: 1,
          status: 'retrying',
          lastError: 'Decryption failed: wrong epoch',
        })
      );
    });

    it('should handle publish failure after successful TEE signing', async () => {
      const entry = createMockEntry();
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('signed-record').toString('base64'),
        newSequenceNumber: '6',
      };
      teeService.republish!.mockResolvedValue([teeResult]);

      // publishSignedRecord fails after all retries
      fetchMock.mockRejectedValue(new Error('Network error'));
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 0, failed: 1 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          consecutiveFailures: 1,
          lastError: expect.stringContaining('Publish failed after successful signing'),
        })
      );
    });

    it('should handle epoch upgrade from TEE result', async () => {
      const entry = createMockEntry({ keyEpoch: 1 });
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const upgradedKeyBase64 = Buffer.from('new-encrypted-key-data').toString('base64');
      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('signed-record').toString('base64'),
        newSequenceNumber: '6',
        upgradedEncryptedKey: upgradedKeyBase64,
        upgradedKeyEpoch: 2,
      };
      teeService.republish!.mockResolvedValue([teeResult]);

      fetchMock.mockResolvedValue(mockResponse(200));
      scheduleRepository.save.mockResolvedValue(entry);
      folderIpnsRepository.update.mockResolvedValue({ affected: 1 });

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 1, failed: 0 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedIpnsKey: Buffer.from(upgradedKeyBase64, 'base64'),
          keyEpoch: 2,
        })
      );
    });

    it('should handle no result from TEE for an entry (undefined result)', async () => {
      const entry = createMockEntry();
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      // TEE returns empty results array (fewer results than entries)
      teeService.republish!.mockResolvedValue([]);
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 0, failed: 1 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          lastError: 'No result from TEE worker',
        })
      );
    });

    it('should handle TEE result with success=false and no error message', async () => {
      const entry = createMockEntry();
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        // no error field
      };
      teeService.republish!.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 0, failed: 1 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          lastError: 'Unknown TEE error',
        })
      );
    });

    it('should process multiple batches when entries exceed BATCH_SIZE', async () => {
      // Create 60 entries (BATCH_SIZE is 50, so this is 2 batches)
      const entries: IpnsRepublishSchedule[] = [];
      for (let i = 0; i < 60; i++) {
        entries.push(createMockEntry({ id: `entry-${i}`, ipnsName: `k51test${i}` }));
      }
      scheduleRepository.find.mockResolvedValue(entries);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      // First batch of 50 entries
      const firstBatchResults: RepublishResult[] = Array.from({ length: 50 }, (_, i) => ({
        ipnsName: `k51test${i}`,
        success: true,
        signedRecord: Buffer.from(`record-${i}`).toString('base64'),
        newSequenceNumber: '6',
      }));
      // Second batch of 10 entries
      const secondBatchResults: RepublishResult[] = Array.from({ length: 10 }, (_, i) => ({
        ipnsName: `k51test${50 + i}`,
        success: true,
        signedRecord: Buffer.from(`record-${50 + i}`).toString('base64'),
        newSequenceNumber: '6',
      }));

      teeService
        .republish!.mockResolvedValueOnce(firstBatchResults)
        .mockResolvedValueOnce(secondBatchResults);

      fetchMock.mockResolvedValue(mockResponse(200));
      scheduleRepository.save.mockResolvedValue({});
      folderIpnsRepository.update.mockResolvedValue({ affected: 1 });

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 60, succeeded: 60, failed: 0 });
      expect(teeService.republish).toHaveBeenCalledTimes(2);
    });
  });

  // ===========================================================================
  // publishSignedRecord()
  // ===========================================================================
  describe('publishSignedRecord', () => {
    const ipnsName = 'k51test123';
    const signedRecordBase64 = Buffer.from('signed-record-bytes').toString('base64');

    it('should succeed on first attempt with 200 response', async () => {
      fetchMock.mockResolvedValue(mockResponse(200));

      await expect(
        service.publishSignedRecord(ipnsName, signedRecordBase64)
      ).resolves.toBeUndefined();

      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledWith(
        `${DELEGATED_ROUTING_URL}/routing/v1/ipns/${ipnsName}`,
        expect.objectContaining({
          method: 'PUT',
          headers: { 'Content-Type': 'application/vnd.ipfs.ipns-record' },
        })
      );
    });

    it('should retry on 429 rate limit and succeed on second attempt', async () => {
      fetchMock
        .mockResolvedValueOnce(mockResponse(429, { 'Retry-After': '2' }))
        .mockResolvedValueOnce(mockResponse(200));

      await expect(
        service.publishSignedRecord(ipnsName, signedRecordBase64)
      ).resolves.toBeUndefined();

      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('should use exponential backoff when 429 has no Retry-After header', async () => {
      fetchMock.mockResolvedValueOnce(mockResponse(429)).mockResolvedValueOnce(mockResponse(200));

      await expect(
        service.publishSignedRecord(ipnsName, signedRecordBase64)
      ).resolves.toBeUndefined();

      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('should throw after non-200, non-429 response after all retries', async () => {
      fetchMock.mockResolvedValue(mockResponse(500));

      await expect(service.publishSignedRecord(ipnsName, signedRecordBase64)).rejects.toThrow(
        'Delegated routing returned 500'
      );
    });

    it('should retry on network error and throw after all retries', async () => {
      fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));

      await expect(service.publishSignedRecord(ipnsName, signedRecordBase64)).rejects.toThrow(
        'ECONNREFUSED'
      );

      // 3 attempts total (maxPublishRetries = 3)
      expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    it('should succeed after intermittent network error', async () => {
      fetchMock
        .mockRejectedValueOnce(new Error('Timeout'))
        .mockResolvedValueOnce(mockResponse(200));

      await expect(
        service.publishSignedRecord(ipnsName, signedRecordBase64)
      ).resolves.toBeUndefined();

      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('should throw generic error if lastError is null after retries', async () => {
      // This covers the edge case where the loop finishes without setting lastError
      // In practice this should not happen, but the code has a fallback
      // We can test by having all attempts return 429 (which does `continue`, not `throw`)
      fetchMock.mockResolvedValue(mockResponse(429));

      // After 3 attempts of 429, the loop ends. The last iteration's 429 does `continue`
      // but doesn't set lastError. However it calls delay and loops. After max retries,
      // it falls through. Since 429 does `continue` instead of throw, lastError stays null.
      await expect(service.publishSignedRecord(ipnsName, signedRecordBase64)).rejects.toThrow(
        'Publish failed after retries'
      );
    });
  });

  // ===========================================================================
  // enrollFolder()
  // ===========================================================================
  describe('enrollFolder', () => {
    const userId = 'user-uuid-1';
    const ipnsName = 'k51test123';
    const encryptedIpnsKey = Buffer.from('encrypted-key');
    const keyEpoch = 1;
    const latestCid = 'bafkrei123';
    const sequenceNumber = '5';

    it('should create new enrollment when none exists', async () => {
      scheduleRepository.findOne.mockResolvedValue(null);
      const createdSchedule = createMockEntry();
      scheduleRepository.create.mockReturnValue(createdSchedule);
      scheduleRepository.save.mockResolvedValue(createdSchedule);

      await service.enrollFolder(
        userId,
        ipnsName,
        encryptedIpnsKey,
        keyEpoch,
        latestCid,
        sequenceNumber
      );

      expect(scheduleRepository.findOne).toHaveBeenCalledWith({
        where: { userId, ipnsName },
      });
      expect(scheduleRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId,
          ipnsName,
          encryptedIpnsKey,
          keyEpoch,
          latestCid,
          sequenceNumber,
          status: 'active',
          consecutiveFailures: 0,
          lastError: null,
          lastRepublishAt: null,
        })
      );
      expect(scheduleRepository.save).toHaveBeenCalledWith(createdSchedule);
    });

    it('should update existing enrollment', async () => {
      const existing = createMockEntry({
        encryptedIpnsKey: Buffer.from('old-key'),
        keyEpoch: 0,
        latestCid: 'old-cid',
        sequenceNumber: '1',
      });
      scheduleRepository.findOne.mockResolvedValue(existing);
      scheduleRepository.save.mockResolvedValue(existing);

      const newKey = Buffer.from('new-encrypted-key');
      await service.enrollFolder(userId, ipnsName, newKey, 2, 'bafkrei-new', '10');

      expect(scheduleRepository.create).not.toHaveBeenCalled();
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedIpnsKey: newKey,
          keyEpoch: 2,
          latestCid: 'bafkrei-new',
          sequenceNumber: '10',
        })
      );
    });
  });

  // ===========================================================================
  // getHealthStats()
  // ===========================================================================
  describe('getHealthStats', () => {
    it('should return aggregate stats, lastRunAt, epoch, and tee health', async () => {
      scheduleRepository.count
        .mockResolvedValueOnce(10) // pending (active)
        .mockResolvedValueOnce(3) // failed (retrying)
        .mockResolvedValueOnce(1); // stale

      const lastRunDate = new Date('2026-01-15');
      scheduleRepository.findOne.mockResolvedValue({
        lastRepublishAt: lastRunDate,
      });

      teeKeyStateService.getCurrentState!.mockResolvedValue(
        createMockTeeState({ currentEpoch: 5 })
      );
      teeService.getHealth!.mockResolvedValue({ healthy: true, epoch: 5 });

      const result = await service.getHealthStats();

      expect(result).toEqual({
        pending: 10,
        failed: 3,
        stale: 1,
        lastRunAt: lastRunDate,
        currentEpoch: 5,
        teeHealthy: true,
      });
    });

    it('should return null lastRunAt when no active entries with lastRepublishAt', async () => {
      scheduleRepository.count.mockResolvedValue(0);
      scheduleRepository.findOne.mockResolvedValue(null);
      teeKeyStateService.getCurrentState!.mockResolvedValue(null);
      teeService.getHealth!.mockResolvedValue({ healthy: true, epoch: 1 });

      const result = await service.getHealthStats();

      expect(result.lastRunAt).toBeNull();
      expect(result.currentEpoch).toBeNull();
    });

    it('should return teeHealthy=false when TEE health check throws', async () => {
      scheduleRepository.count.mockResolvedValue(0);
      scheduleRepository.findOne.mockResolvedValue(null);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());
      teeService.getHealth!.mockRejectedValue(new Error('Connection refused'));

      const result = await service.getHealthStats();

      expect(result.teeHealthy).toBe(false);
    });

    it('should return teeHealthy=false when TEE reports unhealthy', async () => {
      scheduleRepository.count.mockResolvedValue(0);
      scheduleRepository.findOne.mockResolvedValue(null);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());
      teeService.getHealth!.mockResolvedValue({ healthy: false, epoch: 1 });

      const result = await service.getHealthStats();

      expect(result.teeHealthy).toBe(false);
    });

    it('should return currentEpoch from tee state when available', async () => {
      scheduleRepository.count.mockResolvedValue(0);
      scheduleRepository.findOne.mockResolvedValue(null);
      teeKeyStateService.getCurrentState!.mockResolvedValue(
        createMockTeeState({ currentEpoch: 7 })
      );
      teeService.getHealth!.mockResolvedValue({ healthy: true, epoch: 7 });

      const result = await service.getHealthStats();

      expect(result.currentEpoch).toBe(7);
    });
  });

  // ===========================================================================
  // reactivateStaleEntries()
  // ===========================================================================
  describe('reactivateStaleEntries', () => {
    it('should reactivate stale entries and return count', async () => {
      scheduleRepository.update.mockResolvedValue({ affected: 5 });

      const count = await service.reactivateStaleEntries();

      expect(count).toBe(5);
      expect(scheduleRepository.update).toHaveBeenCalledWith(
        { status: 'stale' },
        expect.objectContaining({
          status: 'active',
          consecutiveFailures: 0,
          lastError: null,
        })
      );
    });

    it('should return 0 when no stale entries exist', async () => {
      scheduleRepository.update.mockResolvedValue({ affected: 0 });

      const count = await service.reactivateStaleEntries();

      expect(count).toBe(0);
    });

    it('should return 0 when affected is undefined', async () => {
      scheduleRepository.update.mockResolvedValue({});

      const count = await service.reactivateStaleEntries();

      expect(count).toBe(0);
    });
  });

  // ===========================================================================
  // handleEntryFailure (tested via processRepublishBatch)
  // ===========================================================================
  describe('handleEntryFailure (via processRepublishBatch)', () => {
    it('should increment consecutiveFailures and set retrying status', async () => {
      const entry = createMockEntry({ consecutiveFailures: 3 });
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Some error',
      };
      teeService.republish!.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      await service.processRepublishBatch();

      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          consecutiveFailures: 4,
          status: 'retrying',
          lastError: 'Some error',
        })
      );
    });

    it('should mark entry as stale after MAX_CONSECUTIVE_FAILURES (10)', async () => {
      const entry = createMockEntry({ consecutiveFailures: 9 });
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Persistent failure',
      };
      teeService.republish!.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      await service.processRepublishBatch();

      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          consecutiveFailures: 10,
          status: 'stale',
        })
      );
    });

    it('should truncate error messages longer than 500 characters', async () => {
      const entry = createMockEntry();
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const longError = 'x'.repeat(1000);
      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: longError,
      };
      teeService.republish!.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      await service.processRepublishBatch();

      const savedEntry = scheduleRepository.save.mock.calls[0][0];
      expect(savedEntry.lastError.length).toBe(500);
    });

    it('should apply exponential backoff for retrying entries', async () => {
      const entry = createMockEntry({ consecutiveFailures: 2 });
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Temporary error',
      };
      teeService.republish!.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      const beforeTime = Date.now();
      await service.processRepublishBatch();

      const savedEntry = scheduleRepository.save.mock.calls[0][0];
      // consecutiveFailures is now 3, so backoff = min(30 * 2^3, 3600) = 240 seconds
      const expectedMinTime = beforeTime + 240 * 1000;
      expect(savedEntry.nextRepublishAt.getTime()).toBeGreaterThanOrEqual(expectedMinTime - 1000);
      expect(savedEntry.nextRepublishAt.getTime()).toBeLessThanOrEqual(expectedMinTime + 5000);
    });
  });

  // ===========================================================================
  // syncFolderIpnsSequence (tested via processRepublishBatch)
  // ===========================================================================
  describe('syncFolderIpnsSequence (via processRepublishBatch)', () => {
    it('should not break processing if folderIpns update fails', async () => {
      const entry = createMockEntry();
      scheduleRepository.find.mockResolvedValue([entry]);
      teeKeyStateService.getCurrentState!.mockResolvedValue(createMockTeeState());

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('signed').toString('base64'),
        newSequenceNumber: '6',
      };
      teeService.republish!.mockResolvedValue([teeResult]);
      fetchMock.mockResolvedValue(mockResponse(200));
      scheduleRepository.save.mockResolvedValue(entry);

      // folderIpns update throws -- should not affect result
      folderIpnsRepository.update.mockRejectedValue(new Error('DB connection lost'));

      const result = await service.processRepublishBatch();

      // Should still count as succeeded since the IPNS publish was successful
      expect(result.succeeded).toBe(1);
    });
  });

  // ===========================================================================
  // Constructor / config
  // ===========================================================================
  describe('constructor', () => {
    it('should use default delegated routing URL when not configured', async () => {
      const moduleDefaults: TestingModule = await Test.createTestingModule({
        providers: [
          RepublishService,
          {
            provide: getRepositoryToken(IpnsRepublishSchedule),
            useValue: { find: jest.fn().mockResolvedValue([]) },
          },
          {
            provide: getRepositoryToken(FolderIpns),
            useValue: { update: jest.fn() },
          },
          { provide: TeeService, useValue: { republish: jest.fn() } },
          { provide: TeeKeyStateService, useValue: { getCurrentState: jest.fn() } },
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn((_key: string, defaultValue?: string) => defaultValue),
            },
          },
        ],
      }).compile();

      const defaultService = moduleDefaults.get<RepublishService>(RepublishService);

      // Trigger a publish to check the URL used
      fetchMock.mockResolvedValue(mockResponse(200));
      await defaultService.publishSignedRecord('k51test', Buffer.from('test').toString('base64'));

      expect(fetchMock).toHaveBeenCalledWith(
        'https://delegated-ipfs.dev/routing/v1/ipns/k51test',
        expect.any(Object)
      );
    });
  });
});
