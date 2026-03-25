import { Test, TestingModule } from '@nestjs/testing';
import { MigrationController } from './migration.controller';
import { MigrationService } from './migration.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RequestWithUser } from '../common/types';
import { StartMigrationDto } from './dto/start-migration.dto';
import { MigrationStatusDto } from './dto/migration-status.dto';

describe('MigrationController', () => {
  let controller: MigrationController;
  let migrationService: jest.Mocked<MigrationService>;

  const mockUser = { id: 'user-uuid-123' };

  const mockRequest = {
    user: mockUser,
  } as unknown as RequestWithUser;

  beforeEach(async () => {
    const mockMigrationService = {
      startMigration: jest.fn(),
      getStatus: jest.fn(),
      pauseMigration: jest.fn(),
      resumeMigration: jest.fn(),
      cancelMigration: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [MigrationController],
      providers: [
        {
          provide: MigrationService,
          useValue: mockMigrationService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<MigrationController>(MigrationController);
    migrationService = module.get(MigrationService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('startMigration', () => {
    const dto: StartMigrationDto = {
      sourceConfigEncrypted: 'encrypted-source',
      destConfigEncrypted: 'encrypted-dest',
    };

    it('should call migrationService.startMigration with user id and dto', async () => {
      migrationService.startMigration.mockResolvedValue('migration-uuid-1');

      await controller.startMigration(mockRequest, dto);

      expect(migrationService.startMigration).toHaveBeenCalledWith('user-uuid-123', dto);
    });

    it('should return object with migrationId', async () => {
      migrationService.startMigration.mockResolvedValue('migration-uuid-1');

      const result = await controller.startMigration(mockRequest, dto);

      expect(result).toEqual({ migrationId: 'migration-uuid-1' });
    });

    it('should propagate errors from service', async () => {
      migrationService.startMigration.mockRejectedValue(new Error('conflict'));

      await expect(controller.startMigration(mockRequest, dto)).rejects.toThrow('conflict');
    });
  });

  describe('getStatus', () => {
    it('should call migrationService.getStatus with user id', async () => {
      migrationService.getStatus.mockResolvedValue(null);

      await controller.getStatus(mockRequest);

      expect(migrationService.getStatus).toHaveBeenCalledWith('user-uuid-123');
    });

    it('should return MigrationStatusDto when migration exists', async () => {
      const statusDto: MigrationStatusDto = {
        id: 'migration-uuid-1',
        status: 'running',
        totalCids: 10,
        migratedCids: 3,
        failedCids: 0,
        createdAt: '2026-03-24T12:00:00.000Z',
        completedAt: null,
      };
      migrationService.getStatus.mockResolvedValue(statusDto);

      const result = await controller.getStatus(mockRequest);

      expect(result).toEqual(statusDto);
    });

    it('should return null when no migration exists', async () => {
      migrationService.getStatus.mockResolvedValue(null);

      const result = await controller.getStatus(mockRequest);

      expect(result).toBeNull();
    });
  });

  describe('pauseMigration', () => {
    const migrationId = 'migration-uuid-1';

    it('should call migrationService.pauseMigration with user id and migration id', async () => {
      migrationService.pauseMigration.mockResolvedValue(undefined);

      await controller.pauseMigration(mockRequest, migrationId);

      expect(migrationService.pauseMigration).toHaveBeenCalledWith('user-uuid-123', migrationId);
    });

    it('should return message confirming pause', async () => {
      migrationService.pauseMigration.mockResolvedValue(undefined);

      const result = await controller.pauseMigration(mockRequest, migrationId);

      expect(result).toEqual({ message: 'Migration paused' });
    });

    it('should propagate errors from service', async () => {
      migrationService.pauseMigration.mockRejectedValue(new Error('not found'));

      await expect(controller.pauseMigration(mockRequest, migrationId)).rejects.toThrow(
        'not found'
      );
    });
  });

  describe('resumeMigration', () => {
    const migrationId = 'migration-uuid-1';

    it('should call migrationService.resumeMigration with user id and migration id', async () => {
      migrationService.resumeMigration.mockResolvedValue(undefined);

      await controller.resumeMigration(mockRequest, migrationId);

      expect(migrationService.resumeMigration).toHaveBeenCalledWith('user-uuid-123', migrationId);
    });

    it('should return message confirming resume', async () => {
      migrationService.resumeMigration.mockResolvedValue(undefined);

      const result = await controller.resumeMigration(mockRequest, migrationId);

      expect(result).toEqual({ message: 'Migration resumed' });
    });

    it('should propagate errors from service', async () => {
      migrationService.resumeMigration.mockRejectedValue(new Error('conflict'));

      await expect(controller.resumeMigration(mockRequest, migrationId)).rejects.toThrow(
        'conflict'
      );
    });
  });

  describe('cancelMigration', () => {
    const migrationId = 'migration-uuid-1';

    it('should call migrationService.cancelMigration with user id and migration id', async () => {
      migrationService.cancelMigration.mockResolvedValue(undefined);

      await controller.cancelMigration(mockRequest, migrationId);

      expect(migrationService.cancelMigration).toHaveBeenCalledWith('user-uuid-123', migrationId);
    });

    it('should return message confirming cancel', async () => {
      migrationService.cancelMigration.mockResolvedValue(undefined);

      const result = await controller.cancelMigration(mockRequest, migrationId);

      expect(result).toEqual({ message: 'Migration cancelled' });
    });

    it('should propagate errors from service', async () => {
      migrationService.cancelMigration.mockRejectedValue(new Error('already completed'));

      await expect(controller.cancelMigration(mockRequest, migrationId)).rejects.toThrow(
        'already completed'
      );
    });
  });
});
