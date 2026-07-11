import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { RepublishService } from './republish.service';
import { IpnsRepublishSchedule } from './republish-schedule.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { TeeService, RepublishResult } from '../tee/tee.service';
import { TeeKeyStateService } from '../tee/tee-key-state.service';
import { DelegatedRoutingClient } from '../ipns/delegated-routing.client';

// atob is not available in all Node.js test environments
global.atob = (str: string) => Buffer.from(str, 'base64').toString('binary');

describe('RepublishService', () => {
  let service: RepublishService;
  let scheduleRepository: jest.Mocked<Record<string, jest.Mock>>;
  let ipnsRecordRepository: jest.Mocked<Record<string, jest.Mock>>;
  let teeService: { republish: jest.Mock; getHealth: jest.Mock };
  let teeKeyStateService: { getCurrentState: jest.Mock };
  let mockDelegatedRoutingClient: { publish: jest.Mock; resolve: jest.Mock };

  // Query-builder mocks -------------------------------------------------------

  /** QB mock for the schedule select (getDueEntries step 1). */
  let scheduleQBMock: {
    innerJoin: jest.Mock;
    where: jest.Mock;
    andWhere: jest.Mock;
    orderBy: jest.Mock;
    take: jest.Mock;
    getMany: jest.Mock;
  };

  /** QB mock for the record select (getDueEntries step 2). */
  let recordSelectQBMock: {
    where: jest.Mock;
    andWhere: jest.Mock;
    getMany: jest.Mock;
  };

  /** QB mock for the record UPDATE (renewIpnsRecordEol). */
  let recordUpdateQBMock: {
    update: jest.Mock;
    set: jest.Mock;
    where: jest.Mock;
    execute: jest.Mock;
  };

  // Factory helpers -----------------------------------------------------------

  function createMockSchedule(
    overrides: Partial<IpnsRepublishSchedule> = {}
  ): IpnsRepublishSchedule {
    return {
      id: 'entry-uuid-1',
      userId: 'user-uuid-1',
      ipnsName: 'k51test123',
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

  function createMockRecord(overrides: Partial<IpnsRecord> = {}): IpnsRecord {
    return {
      id: 'record-uuid-1',
      userId: 'user-uuid-1',
      ipnsName: 'k51test123',
      latestCid: 'bafkrei123',
      sequenceNumber: '5',
      signedRecord: Buffer.from('signed-record-bytes'),
      encryptedIpnsPrivateKey: Buffer.from('encrypted-data'),
      keyEpoch: 1,
      isRoot: false,
      tombstonedAt: null,
      generation: '0',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    } as IpnsRecord;
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
    // Schedule QB (chained select, getDueEntries step 1)
    scheduleQBMock = {
      innerJoin: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      take: jest.fn().mockReturnThis(),
      getMany: jest.fn().mockResolvedValue([]),
    };

    // Record select QB (getDueEntries step 2)
    recordSelectQBMock = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      getMany: jest.fn().mockResolvedValue([]),
    };

    // Record update QB (renewIpnsRecordEol)
    recordUpdateQBMock = {
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      execute: jest.fn().mockResolvedValue({ affected: 1 }),
    };

    const mockScheduleRepo = {
      createQueryBuilder: jest.fn().mockReturnValue(scheduleQBMock),
      find: jest.fn().mockResolvedValue([]),
      findOne: jest.fn(),
      save: jest.fn(),
      create: jest.fn(),
      count: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };

    // ipnsRecordRepository: SELECT QB uses alias 'r', UPDATE QB uses no alias
    const mockIpnsRecordRepo = {
      createQueryBuilder: jest
        .fn()
        .mockImplementation((alias?: string) => (alias ? recordSelectQBMock : recordUpdateQBMock)),
      find: jest.fn().mockResolvedValue([]),
      update: jest.fn(),
    };

    const mockTeeService = {
      republish: jest.fn(),
      getHealth: jest.fn(),
    };

    const mockTeeKeyStateService = {
      getCurrentState: jest.fn(),
    };

    mockDelegatedRoutingClient = {
      publish: jest.fn().mockResolvedValue(undefined),
      resolve: jest.fn().mockResolvedValue(null),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RepublishService,
        { provide: getRepositoryToken(IpnsRepublishSchedule), useValue: mockScheduleRepo },
        { provide: getRepositoryToken(IpnsRecord), useValue: mockIpnsRecordRepo },
        { provide: TeeService, useValue: mockTeeService },
        { provide: TeeKeyStateService, useValue: mockTeeKeyStateService },
        { provide: DelegatedRoutingClient, useValue: mockDelegatedRoutingClient },
      ],
    }).compile();

    service = module.get<RepublishService>(RepublishService);
    scheduleRepository = module.get(getRepositoryToken(IpnsRepublishSchedule));
    ipnsRecordRepository = module.get(getRepositoryToken(IpnsRecord));
    teeService = module.get(TeeService) as unknown as typeof teeService;
    teeKeyStateService = module.get(TeeKeyStateService) as unknown as typeof teeKeyStateService;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ===========================================================================
  // getDueEntries()
  // ===========================================================================
  describe('getDueEntries', () => {
    it('should return empty array when no schedule entries are due', async () => {
      scheduleRepository.find.mockResolvedValue([]);

      const result = await service.getDueEntries();

      expect(result).toEqual([]);
    });

    it('should query ipns_records with the tombstone + key filter', async () => {
      const schedule = createMockSchedule();
      scheduleRepository.find.mockResolvedValue([schedule]);
      ipnsRecordRepository.find.mockResolvedValue([]);

      await service.getDueEntries();

      expect(ipnsRecordRepository.find).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            ipnsName: expect.anything(),
            tombstonedAt: expect.anything(),
            encryptedIpnsPrivateKey: expect.anything(),
          }),
        })
      );
    });

    it('should return paired { schedule, record } for each due entry', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord();
      scheduleRepository.find.mockResolvedValue([schedule]);
      ipnsRecordRepository.find.mockResolvedValue([record]);

      const result = await service.getDueEntries();

      expect(result).toHaveLength(1);
      expect(result[0]).toMatchObject({ schedule, record });
    });

    it('should NOT pair a record owned by a different user (userId scoping)', async () => {
      // Same ipnsName, different owner. ipnsName uniqueness is app-level, not a DB
      // constraint, so the pairing must key on (userId, ipnsName) — a cross-user
      // record must never pair with this schedule.
      const schedule = createMockSchedule({ userId: 'user-A' });
      const record = createMockRecord({ userId: 'user-B' });
      scheduleRepository.find.mockResolvedValue([schedule]);
      ipnsRecordRepository.find.mockResolvedValue([record]);

      const result = await service.getDueEntries();

      expect(result).toHaveLength(0);
    });

    it('should exclude tombstoned names — a tombstoned record yields no pair', async () => {
      // Schedule is due, but the ipns_records filter (tombstonedAt IS NULL) excludes
      // the record, so it never enters the record map → the schedule drops out of the
      // paired result (defense layer 1).
      const schedule = createMockSchedule();
      scheduleRepository.find.mockResolvedValue([schedule]);
      ipnsRecordRepository.find.mockResolvedValue([]);

      const result = await service.getDueEntries();

      expect(result).toEqual([]);
    });

    it('should filter to active/retrying statuses and next_republish_at <= now', async () => {
      scheduleRepository.find.mockResolvedValue([]);

      await service.getDueEntries();

      expect(scheduleRepository.find).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: expect.anything(),
            nextRepublishAt: expect.anything(),
          }),
          order: { nextRepublishAt: 'ASC' },
          take: 2000,
        })
      );
    });

    it('should skip races: schedules returned but record not found → excluded from pairs', async () => {
      const schedule = createMockSchedule({ ipnsName: 'k51testRaceWindow' });
      scheduleRepository.find.mockResolvedValue([schedule]);
      // Record was tombstoned/removed between the two queries (race window)
      ipnsRecordRepository.find.mockResolvedValue([]);

      const result = await service.getDueEntries();

      expect(result).toHaveLength(0);
    });
  });

  // ===========================================================================
  // processRepublishBatch()
  // ===========================================================================
  describe('processRepublishBatch', () => {
    it('should return zeros when no entries are due', async () => {
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([]);

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 0, succeeded: 0, failed: 0 });
      expect(teeService.republish).not.toHaveBeenCalled();
    });

    it('should build teeEntries from the joined record (signedRecord + encryptedIpnsPrivateKey + keyEpoch + ipnsName only)', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord({
        encryptedIpnsPrivateKey: Buffer.from('enc-key'),
        keyEpoch: 3,
        signedRecord: Buffer.from('canonical-signed-record'),
        sequenceNumber: '7',
      });
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('renewed-signed-record').toString('base64'),
        newSequenceNumber: '7',
      };
      teeService.republish.mockResolvedValue([teeResult]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);

      await service.processRepublishBatch();

      // teeEntries must source ALL signing inputs from the joined record — NOT the schedule
      expect(teeService.republish).toHaveBeenCalledWith([
        expect.objectContaining({
          encryptedIpnsPrivateKey: Buffer.from('enc-key').toString('base64'),
          keyEpoch: 3,
          ipnsName: 'k51test123',
          signedRecord: Buffer.from('canonical-signed-record').toString('base64'),
        }),
      ]);
      // Relay MUST NOT send latestCid/sequenceNumber/currentEpoch/previousEpoch
      const calledWith = teeService.republish.mock.calls[0][0][0] as Record<string, unknown>;
      expect(calledWith).not.toHaveProperty('latestCid');
      expect(calledWith).not.toHaveProperty('sequenceNumber');
      expect(calledWith).not.toHaveProperty('currentEpoch');
      expect(calledWith).not.toHaveProperty('previousEpoch');
    });

    it('should process a successful batch: schedule fields updated, renewIpnsRecordEol called', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord({ sequenceNumber: '5' });
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('renewed-signed-record').toString('base64'),
        newSequenceNumber: '5', // EOL-only: same sequence number
      };
      teeService.republish.mockResolvedValue([teeResult]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 1, failed: 0 });

      // Schedule updated with ONLY scheduling fields (no sequenceNumber/encryptedIpnsPrivateKey)
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          consecutiveFailures: 0,
          status: 'active',
          lastError: null,
          lastRepublishAt: expect.any(Date),
          nextRepublishAt: expect.any(Date),
        })
      );
      const savedSchedule = scheduleRepository.save.mock.calls[0][0] as Record<string, unknown>;
      expect(savedSchedule).not.toHaveProperty('sequenceNumber');
      expect(savedSchedule).not.toHaveProperty('encryptedIpnsPrivateKey');

      // renewIpnsRecordEol QB update called: signed_record updated via equality CAS
      expect(ipnsRecordRepository.createQueryBuilder)
        .toHaveBeenCalledWith
        // no alias → UPDATE QB
        ();
      expect(recordUpdateQBMock.update).toHaveBeenCalled();
      expect(recordUpdateQBMock.set).toHaveBeenCalledWith(
        expect.objectContaining({
          signedRecord: Buffer.from('renewed-signed-record'), // base64-decoded UTF-8 bytes
        })
      );
      expect(recordUpdateQBMock.where).toHaveBeenCalledWith(
        expect.stringContaining('sequence_number = :expected'),
        expect.objectContaining({
          ipnsName: 'k51test123',
          expected: '5', // loaded from record.sequenceNumber
        })
      );
      expect(recordUpdateQBMock.where).toHaveBeenCalledWith(
        expect.stringContaining('tombstoned_at IS NULL'),
        expect.any(Object)
      );
    });

    it('should handle TEE unreachable (teeService.republish throws)', async () => {
      const pairs = [
        { schedule: createMockSchedule(), record: createMockRecord() },
        {
          schedule: createMockSchedule({ id: 'entry-uuid-2', ipnsName: 'k51test456' }),
          record: createMockRecord({ ipnsName: 'k51test456' }),
        },
      ];
      jest.spyOn(service, 'getDueEntries').mockResolvedValue(pairs);

      teeService.republish.mockRejectedValue(new Error('Connection refused'));
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 2, succeeded: 0, failed: 2 });
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
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule: createMockSchedule(), record: createMockRecord() }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Decryption failed: wrong epoch',
      };
      teeService.republish.mockResolvedValue([teeResult]);
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
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule: createMockSchedule(), record: createMockRecord() }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('signed-record').toString('base64'),
        newSequenceNumber: '5',
      };
      teeService.republish.mockResolvedValue([teeResult]);

      mockDelegatedRoutingClient.publish.mockRejectedValue(new Error('Network error'));
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

    it('should write epoch upgrade to ipns_records (not the schedule)', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord({ keyEpoch: 1, sequenceNumber: '5' });
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      const upgradedKeyBase64 = Buffer.from('new-encrypted-key-data').toString('base64');
      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('renewed-record').toString('base64'),
        newSequenceNumber: '5',
        upgradedEncryptedKey: upgradedKeyBase64,
        upgradedKeyEpoch: 2,
      };
      teeService.republish.mockResolvedValue([teeResult]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);
      ipnsRecordRepository.update.mockResolvedValue({ affected: 1 });

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 1, failed: 0 });

      // Epoch upgrade MUST go to ipns_records, not the schedule — and MUST be scoped
      // to the owner's non-tombstoned row at the loaded epoch (tombstone immutability +
      // userId scope + epoch CAS).
      expect(ipnsRecordRepository.update).toHaveBeenCalledWith(
        expect.objectContaining({ ipnsName: 'k51test123', userId: 'user-uuid-1', keyEpoch: 1 }),
        {
          encryptedIpnsPrivateKey: Buffer.from(upgradedKeyBase64, 'base64'),
          keyEpoch: 2,
        }
      );
      // The upgrade criteria carries a tombstone guard so a tombstoned row is never re-encrypted
      const upgradeCriteria = ipnsRecordRepository.update.mock.calls[0][0] as Record<
        string,
        unknown
      >;
      expect(upgradeCriteria).toHaveProperty('tombstonedAt');

      // The schedule save MUST NOT carry crypto columns
      const savedSchedule = scheduleRepository.save.mock.calls.find(
        (c) => !(c[0] as Record<string, unknown>).consecutiveFailures
      )?.[0] as Record<string, unknown> | undefined;
      if (savedSchedule) {
        expect(savedSchedule).not.toHaveProperty('encryptedIpnsPrivateKey');
        expect(savedSchedule).not.toHaveProperty('keyEpoch');
      }
    });

    it('should route requiresReEnroll to handleEntryFailure (non-fatal, no key material logged)', async () => {
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule: createMockSchedule(), record: createMockRecord() }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        requiresReEnroll: true,
      };
      teeService.republish.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 0, failed: 1 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          consecutiveFailures: 1,
          status: 'retrying',
        })
      );
    });

    it('should handle no result from TEE for an entry (undefined result)', async () => {
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule: createMockSchedule(), record: createMockRecord() }]);

      teeService.republish.mockResolvedValue([]);
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 0, failed: 1 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ lastError: 'No result from TEE worker' })
      );
    });

    it('should handle TEE result with success=false and no error message', async () => {
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule: createMockSchedule(), record: createMockRecord() }]);

      const teeResult: RepublishResult = { ipnsName: 'k51test123', success: false };
      teeService.republish.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 1, succeeded: 0, failed: 1 });
      expect(scheduleRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ lastError: 'Unknown TEE error' })
      );
    });

    it('should process multiple batches when entries exceed BATCH_SIZE', async () => {
      const pairs: Array<{ schedule: IpnsRepublishSchedule; record: IpnsRecord }> = [];
      for (let i = 0; i < 150; i++) {
        pairs.push({
          schedule: createMockSchedule({ id: `entry-${i}`, ipnsName: `k51test${i}` }),
          record: createMockRecord({
            ipnsName: `k51test${i}`,
            signedRecord: Buffer.from(`rec-${i}`),
          }),
        });
      }
      jest.spyOn(service, 'getDueEntries').mockResolvedValue(pairs);

      const firstBatchResults: RepublishResult[] = Array.from({ length: 100 }, (_, i) => ({
        ipnsName: `k51test${i}`,
        success: true,
        signedRecord: Buffer.from(`record-${i}`).toString('base64'),
        newSequenceNumber: '5',
      }));
      const secondBatchResults: RepublishResult[] = Array.from({ length: 50 }, (_, i) => ({
        ipnsName: `k51test${100 + i}`,
        success: true,
        signedRecord: Buffer.from(`record-${100 + i}`).toString('base64'),
        newSequenceNumber: '5',
      }));

      teeService
        .republish!.mockResolvedValueOnce(firstBatchResults)
        .mockResolvedValueOnce(secondBatchResults);

      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue({});

      const result = await service.processRepublishBatch();

      expect(result).toEqual({ processed: 150, succeeded: 150, failed: 0 });
      expect(teeService.republish).toHaveBeenCalledTimes(2);
    });
  });

  // ===========================================================================
  // renewIpnsRecordEol() — equality CAS for EOL-only renewal
  // ===========================================================================
  describe('renewIpnsRecordEol (via processRepublishBatch)', () => {
    it('CAS hit: affected > 0 → signed_record updated, no throw', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord({ sequenceNumber: '5' });
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      const renewedB64 = Buffer.from('new-eol-signed-record').toString('base64');
      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: renewedB64,
        newSequenceNumber: '5',
      };
      teeService.republish.mockResolvedValue([teeResult]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);
      recordUpdateQBMock.execute.mockResolvedValue({ affected: 1 });

      await service.processRepublishBatch();

      expect(recordUpdateQBMock.set).toHaveBeenCalledWith(
        expect.objectContaining({ signedRecord: Buffer.from(renewedB64, 'base64') })
      );
      expect(recordUpdateQBMock.where).toHaveBeenCalledWith(
        expect.stringContaining('sequence_number = :expected'),
        expect.objectContaining({ expected: '5' })
      );
      // The renewal CAS is scoped to the owning user (ipnsName is not globally unique).
      expect(recordUpdateQBMock.where).toHaveBeenCalledWith(
        expect.stringContaining('user_id = :userId'),
        expect.objectContaining({ userId: 'user-uuid-1' })
      );
    });

    it('CAS miss (seq mismatch): affected === 0 → logs debug, no throw, counts as succeeded', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord({ sequenceNumber: '5' });
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('renewed').toString('base64'),
        newSequenceNumber: '5',
      };
      teeService.republish.mockResolvedValue([teeResult]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);
      // Simulate a forward publish that advanced the sequence since the batch loaded
      recordUpdateQBMock.execute.mockResolvedValue({ affected: 0 });

      // Must NOT throw
      const result = await service.processRepublishBatch();
      expect(result.succeeded).toBe(1); // still counted as succeeded (publish succeeded; renewal harmlessly discarded)
    });

    it('CAS tombstoned: affected === 0 (tombstoned_at IS NULL in WHERE) → logs debug, no throw', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord({ sequenceNumber: '5', tombstonedAt: null }); // tombstone enforced at write level
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: true,
        signedRecord: Buffer.from('renewed').toString('base64'),
        newSequenceNumber: '5',
      };
      teeService.republish.mockResolvedValue([teeResult]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);
      // WHERE tombstoned_at IS NULL would reject a tombstoned row → affected 0
      recordUpdateQBMock.execute.mockResolvedValue({ affected: 0 });

      const result = await service.processRepublishBatch();
      expect(result.succeeded).toBe(1); // still counted as succeeded (renewal harmlessly discarded)
    });

    it('renewIpnsRecordEol MUST NOT change sequence_number (EOL-only)', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord({ sequenceNumber: '5' });
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      teeService.republish.mockResolvedValue([
        {
          ipnsName: 'k51test123',
          success: true,
          signedRecord: Buffer.from('renewed').toString('base64'),
          newSequenceNumber: '5',
        },
      ]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);

      await service.processRepublishBatch();

      // set() must NOT include sequenceNumber
      const setArg = recordUpdateQBMock.set.mock.calls[0][0] as Record<string, unknown>;
      expect(setArg).not.toHaveProperty('sequenceNumber');
    });
  });

  // ===========================================================================
  // publishSignedRecord()
  // ===========================================================================
  describe('publishSignedRecord', () => {
    const ipnsName = 'k51test123';
    const signedRecordBase64 = Buffer.from('signed-record-bytes').toString('base64');

    it('should succeed when delegated routing client succeeds', async () => {
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);

      await expect(
        service.publishSignedRecord(ipnsName, signedRecordBase64)
      ).resolves.toBeUndefined();

      expect(mockDelegatedRoutingClient.publish).toHaveBeenCalledTimes(1);
      expect(mockDelegatedRoutingClient.publish).toHaveBeenCalledWith(
        ipnsName,
        expect.any(Uint8Array)
      );
    });

    it('should propagate error when delegated routing client throws', async () => {
      mockDelegatedRoutingClient.publish.mockRejectedValue(new Error('ECONNREFUSED'));

      await expect(service.publishSignedRecord(ipnsName, signedRecordBase64)).rejects.toThrow(
        'ECONNREFUSED'
      );
    });

    it('should decode base64 record to Uint8Array before publishing', async () => {
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);

      await service.publishSignedRecord(ipnsName, signedRecordBase64);

      const passedBytes = mockDelegatedRoutingClient.publish.mock.calls[0][1] as Uint8Array;
      const decoded = Array.from(passedBytes)
        .map((b) => String.fromCharCode(b))
        .join('');
      expect(decoded).toBe('signed-record-bytes');
    });
  });

  // ===========================================================================
  // enrollFolder() — 2-arg scheduling-only
  // ===========================================================================
  describe('enrollFolder', () => {
    const userId = 'user-uuid-1';
    const ipnsName = 'k51test123';

    it('should create new enrollment with only scheduling fields', async () => {
      scheduleRepository.findOne.mockResolvedValue(null);
      const createdSchedule = createMockSchedule();
      scheduleRepository.create.mockReturnValue(createdSchedule);
      scheduleRepository.save.mockResolvedValue(createdSchedule);

      await service.enrollFolder(userId, ipnsName);

      expect(scheduleRepository.findOne).toHaveBeenCalledWith({ where: { userId, ipnsName } });
      expect(scheduleRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId,
          ipnsName,
          status: 'active',
          consecutiveFailures: 0,
          lastError: null,
          lastRepublishAt: null,
        })
      );
      // Must NOT set any crypto column
      const createArg = scheduleRepository.create.mock.calls[0][0] as Record<string, unknown>;
      expect(createArg).not.toHaveProperty('encryptedIpnsPrivateKey');
      expect(createArg).not.toHaveProperty('keyEpoch');
      expect(createArg).not.toHaveProperty('latestCid');
      expect(createArg).not.toHaveProperty('sequenceNumber');
      expect(scheduleRepository.save).toHaveBeenCalledWith(createdSchedule);
    });

    it('should update nextRepublishAt only when updating existing enrollment', async () => {
      const existing = createMockSchedule();
      scheduleRepository.findOne.mockResolvedValue(existing);
      scheduleRepository.save.mockResolvedValue(existing);

      await service.enrollFolder(userId, ipnsName);

      expect(scheduleRepository.create).not.toHaveBeenCalled();
      const saved = scheduleRepository.save.mock.calls[0][0] as Record<string, unknown>;
      expect(saved).toHaveProperty('nextRepublishAt');
      // Must NOT overwrite crypto columns (they live in ipns_records)
      expect(saved).not.toHaveProperty('encryptedIpnsPrivateKey');
      expect(saved).not.toHaveProperty('keyEpoch');
    });
  });

  // ===========================================================================
  // getHealthStats()
  // ===========================================================================
  describe('getHealthStats', () => {
    it('should return aggregate stats, lastRunAt, epoch, and tee health', async () => {
      scheduleRepository.count
        .mockResolvedValueOnce(10)
        .mockResolvedValueOnce(3)
        .mockResolvedValueOnce(1);

      const lastRunDate = new Date('2026-01-15');
      scheduleRepository.findOne.mockResolvedValue({ lastRepublishAt: lastRunDate });
      teeKeyStateService.getCurrentState.mockResolvedValue(createMockTeeState({ currentEpoch: 5 }));
      teeService.getHealth.mockResolvedValue({ healthy: true, epoch: 5 });

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

    it('should return null lastRunAt when no active entries', async () => {
      scheduleRepository.count.mockResolvedValue(0);
      scheduleRepository.findOne.mockResolvedValue(null);
      teeKeyStateService.getCurrentState.mockResolvedValue(null);
      teeService.getHealth.mockResolvedValue({ healthy: true, epoch: 1 });

      const result = await service.getHealthStats();

      expect(result.lastRunAt).toBeNull();
      expect(result.currentEpoch).toBeNull();
    });

    it('should return teeHealthy=false when TEE health check throws', async () => {
      scheduleRepository.count.mockResolvedValue(0);
      scheduleRepository.findOne.mockResolvedValue(null);
      teeKeyStateService.getCurrentState.mockResolvedValue(createMockTeeState());
      teeService.getHealth.mockRejectedValue(new Error('Connection refused'));

      const result = await service.getHealthStats();

      expect(result.teeHealthy).toBe(false);
    });

    it('should return teeHealthy=false when TEE reports unhealthy', async () => {
      scheduleRepository.count.mockResolvedValue(0);
      scheduleRepository.findOne.mockResolvedValue(null);
      teeKeyStateService.getCurrentState.mockResolvedValue(createMockTeeState());
      teeService.getHealth.mockResolvedValue({ healthy: false, epoch: 1 });

      const result = await service.getHealthStats();

      expect(result.teeHealthy).toBe(false);
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
      const schedule = createMockSchedule({ consecutiveFailures: 3 });
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule, record: createMockRecord() }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Some error',
      };
      teeService.republish.mockResolvedValue([teeResult]);
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
      const schedule = createMockSchedule({ consecutiveFailures: 9 });
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule, record: createMockRecord() }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Persistent failure',
      };
      teeService.republish.mockResolvedValue([teeResult]);
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
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule: createMockSchedule(), record: createMockRecord() }]);

      const longError = 'x'.repeat(1000);
      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: longError,
      };
      teeService.republish.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      await service.processRepublishBatch();

      const savedEntry = scheduleRepository.save.mock.calls[0][0] as IpnsRepublishSchedule;
      expect(savedEntry.lastError!.length).toBe(500);
    });

    it('should apply exponential backoff for retrying entries', async () => {
      const schedule = createMockSchedule({ consecutiveFailures: 2 });
      jest
        .spyOn(service, 'getDueEntries')
        .mockResolvedValue([{ schedule, record: createMockRecord() }]);

      const teeResult: RepublishResult = {
        ipnsName: 'k51test123',
        success: false,
        error: 'Temporary error',
      };
      teeService.republish.mockResolvedValue([teeResult]);
      scheduleRepository.save.mockResolvedValue({});

      const beforeTime = Date.now();
      await service.processRepublishBatch();

      const savedEntry = scheduleRepository.save.mock.calls[0][0] as IpnsRepublishSchedule;
      // consecutiveFailures is now 3, so backoff = min(30 * 2^3, 3600) = 240 seconds
      const expectedMinTime = beforeTime + 240 * 1000;
      expect(savedEntry.nextRepublishAt.getTime()).toBeGreaterThanOrEqual(expectedMinTime - 1000);
      expect(savedEntry.nextRepublishAt.getTime()).toBeLessThanOrEqual(expectedMinTime + 5000);
    });
  });

  // ===========================================================================
  // renewIpnsRecordEol resilience (via processRepublishBatch)
  // ===========================================================================
  describe('renewIpnsRecordEol resilience (via processRepublishBatch)', () => {
    it('should not break processing if renewIpnsRecordEol QB throws (non-fatal)', async () => {
      const schedule = createMockSchedule();
      const record = createMockRecord();
      jest.spyOn(service, 'getDueEntries').mockResolvedValue([{ schedule, record }]);

      teeService.republish.mockResolvedValue([
        {
          ipnsName: 'k51test123',
          success: true,
          signedRecord: Buffer.from('signed').toString('base64'),
          newSequenceNumber: '5',
        },
      ]);
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);
      scheduleRepository.save.mockResolvedValue(schedule);

      // renewIpnsRecordEol QB throws — should not affect result
      recordUpdateQBMock.execute.mockRejectedValue(new Error('DB connection lost'));

      const result = await service.processRepublishBatch();

      // Still counts as succeeded since the IPNS publish was successful
      expect(result.succeeded).toBe(1);
    });
  });

  // ===========================================================================
  // Constructor / delegated routing delegation
  // ===========================================================================
  describe('constructor', () => {
    it('should delegate publishing to DelegatedRoutingClient', async () => {
      mockDelegatedRoutingClient.publish.mockResolvedValue(undefined);

      await service.publishSignedRecord('k51test', Buffer.from('test').toString('base64'));

      expect(mockDelegatedRoutingClient.publish).toHaveBeenCalledWith(
        'k51test',
        expect.any(Uint8Array)
      );
    });
  });
});
