import {
  Injectable,
  Logger,
  ConflictException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { InjectQueue } from '@nestjs/bullmq';
import { Repository, In } from 'typeorm';
import { Queue } from 'bullmq';
import { PinMigration, MigrationStatus } from './migration.entity';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { StartMigrationDto } from './dto/start-migration.dto';
import { MigrationStatusDto } from './dto/migration-status.dto';

@Injectable()
export class MigrationService {
  private readonly logger = new Logger(MigrationService.name);

  constructor(
    @InjectRepository(PinMigration)
    private readonly migrationRepo: Repository<PinMigration>,
    @InjectRepository(PinnedCid)
    private readonly pinnedCidRepo: Repository<PinnedCid>,
    @InjectQueue('pin-migration')
    private readonly migrationQueue: Queue
  ) {}

  /**
   * Start a new pin migration for a user.
   * Prevents concurrent migrations (only one active migration at a time).
   */
  async startMigration(userId: string, dto: StartMigrationDto): Promise<string> {
    // Check for existing active migration
    const activeMigration = await this.migrationRepo.findOne({
      where: {
        userId,
        status: In(['pending', 'running', 'paused'] as MigrationStatus[]),
      },
    });

    if (activeMigration) {
      throw new ConflictException(
        'An active migration already exists. Complete or cancel it before starting a new one.'
      );
    }

    // Count pinned CIDs for this user
    const totalCids = await this.pinnedCidRepo.count({ where: { userId } });

    // Create migration entity
    const migration = this.migrationRepo.create({
      userId,
      status: 'pending' as MigrationStatus,
      totalCids,
      migratedCids: 0,
      failedCids: 0,
      sourceConfigEncrypted: dto.sourceConfigEncrypted,
      destConfigEncrypted: dto.destConfigEncrypted,
      failedCidList: null,
      completedAt: null,
    });

    const saved = await this.migrationRepo.save(migration);

    // Enqueue BullMQ job
    await this.migrationQueue.add('pin-migration', { migrationId: saved.id });

    this.logger.log(`Migration ${saved.id} started for user ${userId} with ${totalCids} CIDs`);

    return saved.id;
  }

  /**
   * Get the latest migration status for a user.
   */
  async getStatus(userId: string): Promise<MigrationStatusDto | null> {
    const migration = await this.migrationRepo.findOne({
      where: { userId },
      order: { createdAt: 'DESC' },
    });

    if (!migration) {
      return null;
    }

    return {
      id: migration.id,
      status: migration.status,
      totalCids: migration.totalCids,
      migratedCids: migration.migratedCids,
      failedCids: migration.failedCids,
      createdAt: migration.createdAt.toISOString(),
      completedAt: migration.completedAt?.toISOString() ?? null,
    };
  }

  /**
   * Pause an active migration.
   * The BullMQ processor checks status before processing each batch.
   */
  async pauseMigration(userId: string, migrationId: string): Promise<void> {
    const migration = await this.findUserMigration(userId, migrationId);

    if (migration.status !== 'running' && migration.status !== 'pending') {
      throw new ConflictException(`Cannot pause migration in '${migration.status}' status`);
    }

    await this.migrationRepo.update(migrationId, {
      status: 'paused' as MigrationStatus,
    });

    this.logger.log(`Migration ${migrationId} paused`);
  }

  /**
   * Resume a paused migration.
   */
  async resumeMigration(userId: string, migrationId: string): Promise<void> {
    const migration = await this.findUserMigration(userId, migrationId);

    if (migration.status !== 'paused') {
      throw new ConflictException(`Cannot resume migration in '${migration.status}' status`);
    }

    await this.migrationRepo.update(migrationId, {
      status: 'running' as MigrationStatus,
    });

    // Re-enqueue job to continue processing
    await this.migrationQueue.add('pin-migration', { migrationId });

    this.logger.log(`Migration ${migrationId} resumed`);
  }

  /**
   * Cancel a migration.
   */
  async cancelMigration(userId: string, migrationId: string): Promise<void> {
    const migration = await this.findUserMigration(userId, migrationId);

    if (migration.status === 'completed' || migration.status === 'cancelled') {
      throw new ConflictException(`Cannot cancel migration in '${migration.status}' status`);
    }

    await this.migrationRepo.update(migrationId, {
      status: 'cancelled' as MigrationStatus,
    });

    this.logger.log(`Migration ${migrationId} cancelled`);
  }

  /**
   * Update migration progress counters.
   * Called by the BullMQ processor after each batch.
   */
  async updateProgress(
    migrationId: string,
    migratedDelta: number,
    failedDelta: number,
    failedCids?: string[]
  ): Promise<void> {
    const migration = await this.migrationRepo.findOneOrFail({
      where: { id: migrationId },
    });

    migration.migratedCids += migratedDelta;

    if (failedCids && failedCids.length > 0) {
      const existingList = migration.failedCidList ? migration.failedCidList.split(',') : [];
      existingList.push(...failedCids);
      const dedupedList = [...new Set(existingList)];
      migration.failedCidList = dedupedList.join(',');
      // The deduped list is the source of truth for the failed count, so
      // re-reported CIDs (e.g. retried batches) never inflate it.
      migration.failedCids = dedupedList.length;
    } else {
      migration.failedCids += failedDelta;
    }

    // Clamp so migrated + failed never exceeds totalCids. Guards against
    // double-reported batches (e.g. an HTTP timeout abort counted as failed
    // while the TEE worker actually completed the batch and it later succeeds).
    if (
      migration.totalCids > 0 &&
      migration.migratedCids + migration.failedCids > migration.totalCids
    ) {
      migration.migratedCids = Math.max(0, migration.totalCids - migration.failedCids);
    }

    await this.migrationRepo.save(migration);
  }

  /**
   * Find a migration belonging to a specific user.
   * Throws NotFoundException if not found, ForbiddenException if wrong user.
   */
  private async findUserMigration(userId: string, migrationId: string): Promise<PinMigration> {
    const migration = await this.migrationRepo.findOne({
      where: { id: migrationId },
    });

    if (!migration) {
      throw new NotFoundException(`Migration ${migrationId} not found`);
    }

    if (migration.userId !== userId) {
      throw new ForbiddenException('Migration does not belong to this user');
    }

    return migration;
  }
}
