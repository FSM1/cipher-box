import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { TeeKeyStateService } from './tee-key-state.service';
import { TeeKeyState } from './tee-key-state.entity';
import { TeeKeyRotationLog } from './tee-key-rotation-log.entity';

const GRACE_PERIOD_MS = 4 * 7 * 24 * 60 * 60 * 1000; // 4 weeks

describe('TeeKeyStateService', () => {
  let service: TeeKeyStateService;
  let mockKeyStateRepo: {
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
  };
  let mockRotationLogRepo: {
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
  };
  let mockDataSource: {
    transaction: jest.Mock;
  };

  // --- Test data ---
  const testPublicKey = Buffer.from('04' + 'ab'.repeat(64), 'hex');
  const testPublicKey2 = Buffer.from('04' + 'cd'.repeat(64), 'hex');

  const baseMockState: TeeKeyState = {
    id: 'state-uuid-1',
    currentEpoch: 1,
    currentPublicKey: testPublicKey,
    previousEpoch: null,
    previousPublicKey: null,
    gracePeriodEndsAt: null,
    createdAt: new Date('2026-01-20T00:00:00.000Z'),
    updatedAt: new Date('2026-01-20T00:00:00.000Z'),
  };

  const mockRotationLog: TeeKeyRotationLog = {
    id: 'log-uuid-1',
    fromEpoch: 1,
    toEpoch: 2,
    fromPublicKey: testPublicKey,
    toPublicKey: testPublicKey2,
    reason: 'scheduled',
    createdAt: new Date('2026-02-01T00:00:00.000Z'),
  };

  beforeEach(async () => {
    mockKeyStateRepo = {
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
    };

    mockRotationLogRepo = {
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
    };

    mockDataSource = {
      transaction: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TeeKeyStateService,
        {
          provide: getRepositoryToken(TeeKeyState),
          useValue: mockKeyStateRepo,
        },
        {
          provide: getRepositoryToken(TeeKeyRotationLog),
          useValue: mockRotationLogRepo,
        },
        {
          provide: DataSource,
          useValue: mockDataSource,
        },
      ],
    }).compile();

    service = module.get<TeeKeyStateService>(TeeKeyStateService);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  // ─── getCurrentState ──────────────────────────────────────────────

  describe('getCurrentState()', () => {
    it('should return null when table is empty', async () => {
      mockKeyStateRepo.find.mockResolvedValue([]);

      const result = await service.getCurrentState();

      expect(result).toBeNull();
      expect(mockKeyStateRepo.find).toHaveBeenCalledWith({ take: 1 });
    });

    it('should return the first state when table is non-empty', async () => {
      mockKeyStateRepo.find.mockResolvedValue([baseMockState]);

      const result = await service.getCurrentState();

      expect(result).toEqual(baseMockState);
      expect(mockKeyStateRepo.find).toHaveBeenCalledWith({ take: 1 });
    });
  });

  // ─── getTeeKeysDto ────────────────────────────────────────────────

  describe('getTeeKeysDto()', () => {
    it('should return null when no state exists', async () => {
      mockKeyStateRepo.find.mockResolvedValue([]);

      const result = await service.getTeeKeysDto();

      expect(result).toBeNull();
    });

    it('should return formatted DTO with null previousPublicKey', async () => {
      mockKeyStateRepo.find.mockResolvedValue([baseMockState]);

      const result = await service.getTeeKeysDto();

      expect(result).toEqual({
        currentEpoch: 1,
        currentPublicKey: testPublicKey.toString('hex'),
        previousEpoch: null,
        previousPublicKey: null,
      });
    });

    it('should return formatted DTO with previousPublicKey present', async () => {
      const stateWithPrevious: TeeKeyState = {
        ...baseMockState,
        currentEpoch: 2,
        previousEpoch: 1,
        previousPublicKey: testPublicKey2,
        gracePeriodEndsAt: new Date('2026-03-01T00:00:00.000Z'),
      };
      mockKeyStateRepo.find.mockResolvedValue([stateWithPrevious]);

      const result = await service.getTeeKeysDto();

      expect(result).toEqual({
        currentEpoch: 2,
        currentPublicKey: testPublicKey.toString('hex'),
        previousEpoch: 1,
        previousPublicKey: testPublicKey2.toString('hex'),
      });
    });
  });

  // ─── initializeEpoch ──────────────────────────────────────────────

  describe('initializeEpoch()', () => {
    it('should create initial state when table is empty', async () => {
      mockKeyStateRepo.find.mockResolvedValue([]);
      const createdEntity = {
        ...baseMockState,
        currentEpoch: 0,
        currentPublicKey: Buffer.from(testPublicKey),
      };
      mockKeyStateRepo.create.mockReturnValue(createdEntity);
      mockKeyStateRepo.save.mockResolvedValue(createdEntity);

      const result = await service.initializeEpoch(0, testPublicKey);

      expect(result).toEqual(createdEntity);
      expect(mockKeyStateRepo.create).toHaveBeenCalledWith({
        currentEpoch: 0,
        currentPublicKey: Buffer.from(testPublicKey),
        previousEpoch: null,
        previousPublicKey: null,
        gracePeriodEndsAt: null,
      });
      expect(mockKeyStateRepo.save).toHaveBeenCalledWith(createdEntity);
    });

    it('should throw if state is already initialized', async () => {
      mockKeyStateRepo.find.mockResolvedValue([baseMockState]);

      await expect(service.initializeEpoch(0, testPublicKey)).rejects.toThrow(
        'TEE key state already initialized. Use rotateEpoch for updates.'
      );
      expect(mockKeyStateRepo.create).not.toHaveBeenCalled();
      expect(mockKeyStateRepo.save).not.toHaveBeenCalled();
    });
  });

  // ─── rotateEpoch ──────────────────────────────────────────────────

  describe('rotateEpoch()', () => {
    let mockTxKeyStateRepo: { find: jest.Mock; save: jest.Mock };
    let mockTxRotationLogRepo: { create: jest.Mock; save: jest.Mock };
    let mockManager: { getRepository: jest.Mock };

    beforeEach(() => {
      mockTxKeyStateRepo = {
        find: jest.fn(),
        save: jest.fn(),
      };
      mockTxRotationLogRepo = {
        create: jest.fn(),
        save: jest.fn(),
      };
      mockManager = {
        getRepository: jest.fn((entity) => {
          if (entity === TeeKeyState) return mockTxKeyStateRepo;
          if (entity === TeeKeyRotationLog) return mockTxRotationLogRepo;
          throw new Error(`Unexpected entity: ${entity}`);
        }),
      };

      // Make transaction call the callback with the mock manager
      // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
      mockDataSource.transaction.mockImplementation(async (cb: Function) => {
        return cb(mockManager);
      });
    });

    it('should rotate epoch successfully and create rotation log', async () => {
      const existingState: TeeKeyState = { ...baseMockState };
      mockTxKeyStateRepo.find.mockResolvedValue([existingState]);

      const logEntry = { ...mockRotationLog };
      mockTxRotationLogRepo.create.mockReturnValue(logEntry);
      mockTxRotationLogRepo.save.mockResolvedValue(logEntry);

      const savedState: TeeKeyState = {
        ...existingState,
        previousEpoch: 1,
        previousPublicKey: testPublicKey,
        currentEpoch: 2,
        currentPublicKey: Buffer.from(testPublicKey2),
      };
      mockTxKeyStateRepo.save.mockResolvedValue(savedState);

      const dateSpy = jest
        .spyOn(Date, 'now')
        .mockReturnValue(new Date('2026-02-01T00:00:00.000Z').getTime());

      const result = await service.rotateEpoch(2, testPublicKey2, 'scheduled');

      expect(result).toEqual(savedState);

      // Verify rotation log was created
      expect(mockTxRotationLogRepo.create).toHaveBeenCalledWith({
        fromEpoch: 1,
        toEpoch: 2,
        fromPublicKey: testPublicKey,
        toPublicKey: Buffer.from(testPublicKey2),
        reason: 'scheduled',
      });
      expect(mockTxRotationLogRepo.save).toHaveBeenCalledWith(logEntry);

      // Verify state was updated (mutated in place)
      expect(existingState.previousEpoch).toBe(1);
      expect(existingState.previousPublicKey).toEqual(testPublicKey);
      expect(existingState.currentEpoch).toBe(2);
      expect(existingState.currentPublicKey).toEqual(Buffer.from(testPublicKey2));
      expect(existingState.gracePeriodEndsAt).toEqual(
        new Date(new Date('2026-02-01T00:00:00.000Z').getTime() + GRACE_PERIOD_MS)
      );

      expect(mockTxKeyStateRepo.save).toHaveBeenCalledWith(existingState);

      dateSpy.mockRestore();
    });

    it('should throw if state is not initialized', async () => {
      mockTxKeyStateRepo.find.mockResolvedValue([]);

      await expect(service.rotateEpoch(1, testPublicKey, 'scheduled')).rejects.toThrow(
        'Cannot rotate: TEE key state not initialized. Call initializeEpoch first.'
      );

      expect(mockTxRotationLogRepo.create).not.toHaveBeenCalled();
      expect(mockTxKeyStateRepo.save).not.toHaveBeenCalled();
    });

    it('should use transaction for atomicity', async () => {
      mockTxKeyStateRepo.find.mockResolvedValue([{ ...baseMockState }]);
      mockTxRotationLogRepo.create.mockReturnValue(mockRotationLog);
      mockTxRotationLogRepo.save.mockResolvedValue(mockRotationLog);
      mockTxKeyStateRepo.save.mockResolvedValue({ ...baseMockState });

      await service.rotateEpoch(2, testPublicKey2, 'manual');

      expect(mockDataSource.transaction).toHaveBeenCalledTimes(1);
      expect(mockManager.getRepository).toHaveBeenCalledWith(TeeKeyState);
      expect(mockManager.getRepository).toHaveBeenCalledWith(TeeKeyRotationLog);
    });
  });

  // ─── isGracePeriodActive ──────────────────────────────────────────

  describe('isGracePeriodActive()', () => {
    it('should return false when no state exists', async () => {
      mockKeyStateRepo.find.mockResolvedValue([]);

      const result = await service.isGracePeriodActive();

      expect(result).toBe(false);
    });

    it('should return false when gracePeriodEndsAt is null', async () => {
      mockKeyStateRepo.find.mockResolvedValue([baseMockState]);

      const result = await service.isGracePeriodActive();

      expect(result).toBe(false);
    });

    it('should return true when grace period is still active', async () => {
      const futureDate = new Date(Date.now() + 1000 * 60 * 60 * 24); // 1 day ahead
      const stateWithGrace: TeeKeyState = {
        ...baseMockState,
        previousEpoch: 1,
        previousPublicKey: testPublicKey2,
        gracePeriodEndsAt: futureDate,
      };
      mockKeyStateRepo.find.mockResolvedValue([stateWithGrace]);

      const result = await service.isGracePeriodActive();

      expect(result).toBe(true);
    });

    it('should return false when grace period has expired', async () => {
      const pastDate = new Date(Date.now() - 1000 * 60 * 60); // 1 hour ago
      const stateExpired: TeeKeyState = {
        ...baseMockState,
        previousEpoch: 1,
        previousPublicKey: testPublicKey2,
        gracePeriodEndsAt: pastDate,
      };
      mockKeyStateRepo.find.mockResolvedValue([stateExpired]);

      const result = await service.isGracePeriodActive();

      expect(result).toBe(false);
    });
  });

  // ─── getRotationHistory ───────────────────────────────────────────

  describe('getRotationHistory()', () => {
    it('should return rotation logs in descending order', async () => {
      const logs = [mockRotationLog];
      mockRotationLogRepo.find.mockResolvedValue(logs);

      const result = await service.getRotationHistory();

      expect(result).toEqual(logs);
      expect(mockRotationLogRepo.find).toHaveBeenCalledWith({
        order: { createdAt: 'DESC' },
        take: 10,
      });
    });

    it('should use default limit of 10', async () => {
      mockRotationLogRepo.find.mockResolvedValue([]);

      await service.getRotationHistory();

      expect(mockRotationLogRepo.find).toHaveBeenCalledWith({
        order: { createdAt: 'DESC' },
        take: 10,
      });
    });

    it('should use custom limit when provided', async () => {
      mockRotationLogRepo.find.mockResolvedValue([]);

      await service.getRotationHistory(5);

      expect(mockRotationLogRepo.find).toHaveBeenCalledWith({
        order: { createdAt: 'DESC' },
        take: 5,
      });
    });

    it('should return empty array when no logs exist', async () => {
      mockRotationLogRepo.find.mockResolvedValue([]);

      const result = await service.getRotationHistory();

      expect(result).toEqual([]);
    });
  });

  // ─── deprecatePreviousEpoch ───────────────────────────────────────

  describe('deprecatePreviousEpoch()', () => {
    it('should return early when no state exists', async () => {
      mockKeyStateRepo.find.mockResolvedValue([]);

      await service.deprecatePreviousEpoch();

      expect(mockKeyStateRepo.save).not.toHaveBeenCalled();
    });

    it('should return early when no previous epoch exists', async () => {
      mockKeyStateRepo.find.mockResolvedValue([{ ...baseMockState }]);

      await service.deprecatePreviousEpoch();

      expect(mockKeyStateRepo.save).not.toHaveBeenCalled();
    });

    it('should not deprecate when grace period is still active', async () => {
      const futureDate = new Date(Date.now() + 1000 * 60 * 60 * 24); // 1 day ahead
      const stateWithActiveGrace: TeeKeyState = {
        ...baseMockState,
        previousEpoch: 1,
        previousPublicKey: testPublicKey2,
        gracePeriodEndsAt: futureDate,
      };
      mockKeyStateRepo.find.mockResolvedValue([stateWithActiveGrace]);

      await service.deprecatePreviousEpoch();

      expect(mockKeyStateRepo.save).not.toHaveBeenCalled();
    });

    it('should deprecate previous epoch when grace period has expired', async () => {
      const pastDate = new Date(Date.now() - 1000 * 60 * 60); // 1 hour ago
      const stateExpiredGrace: TeeKeyState = {
        ...baseMockState,
        currentEpoch: 2,
        previousEpoch: 1,
        previousPublicKey: testPublicKey2,
        gracePeriodEndsAt: pastDate,
      };
      mockKeyStateRepo.find.mockResolvedValue([stateExpiredGrace]);
      mockKeyStateRepo.save.mockResolvedValue(stateExpiredGrace);

      await service.deprecatePreviousEpoch();

      expect(stateExpiredGrace.previousEpoch).toBeNull();
      expect(stateExpiredGrace.previousPublicKey).toBeNull();
      expect(stateExpiredGrace.gracePeriodEndsAt).toBeNull();
      expect(mockKeyStateRepo.save).toHaveBeenCalledWith(stateExpiredGrace);
    });

    it('should deprecate previous epoch when gracePeriodEndsAt is null (no grace period set)', async () => {
      const stateNullGrace: TeeKeyState = {
        ...baseMockState,
        currentEpoch: 2,
        previousEpoch: 1,
        previousPublicKey: testPublicKey2,
        gracePeriodEndsAt: null,
      };
      mockKeyStateRepo.find.mockResolvedValue([stateNullGrace]);
      mockKeyStateRepo.save.mockResolvedValue(stateNullGrace);

      await service.deprecatePreviousEpoch();

      expect(stateNullGrace.previousEpoch).toBeNull();
      expect(stateNullGrace.previousPublicKey).toBeNull();
      expect(stateNullGrace.gracePeriodEndsAt).toBeNull();
      expect(mockKeyStateRepo.save).toHaveBeenCalledWith(stateNullGrace);
    });
  });
});
