import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { Job } from 'bullmq';
import { PinMigration } from './migration.entity';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { MigrationService } from './migration.service';

const BATCH_SIZE = 10;

@Processor('pin-migration')
export class MigrationProcessor extends WorkerHost {
  private readonly logger = new Logger(MigrationProcessor.name);

  constructor(
    @InjectRepository(PinMigration)
    private readonly migrationRepo: Repository<PinMigration>,
    @InjectRepository(PinnedCid)
    private readonly pinnedCidRepo: Repository<PinnedCid>,
    private readonly migrationService: MigrationService,
    private readonly configService: ConfigService
  ) {
    super();
  }

  async process(job: Job<{ migrationId: string }>): Promise<void> {
    const { migrationId } = job.data;

    const migration = await this.migrationRepo.findOneOrFail({
      where: { id: migrationId },
    });

    // Mark as running
    if (migration.status === 'pending') {
      await this.migrationRepo.update(migrationId, { status: 'running' });
    }

    // Get all CIDs for user
    const pinnedCids = await this.pinnedCidRepo.find({
      where: { userId: migration.userId },
    });

    const TEE_URL = this.configService.get<string>('TEE_WORKER_URL');
    const TEE_SECRET = this.configService.get<string>('TEE_WORKER_SECRET');

    if (!TEE_URL || !TEE_SECRET) {
      this.logger.error('TEE_WORKER_URL or TEE_WORKER_SECRET not configured');
      await this.migrationRepo.update(migrationId, { status: 'failed' });
      return;
    }

    this.logger.log(
      `Processing migration ${migrationId}: ${pinnedCids.length} CIDs in batches of ${BATCH_SIZE}`
    );

    for (let i = 0; i < pinnedCids.length; i += BATCH_SIZE) {
      // Check if paused or cancelled before processing each batch
      const current = await this.migrationRepo.findOneOrFail({
        where: { id: migrationId },
      });
      if (current.status === 'paused' || current.status === 'cancelled') {
        this.logger.log(`Migration ${migrationId} ${current.status} -- stopping processing`);
        break;
      }

      const batch = pinnedCids.slice(i, i + BATCH_SIZE);
      const cids = batch.map((p) => p.cid);

      try {
        const response = await fetch(`${TEE_URL}/migrate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${TEE_SECRET}`,
          },
          body: JSON.stringify({
            cids,
            sourceConfigEncrypted: migration.sourceConfigEncrypted,
            destConfigEncrypted: migration.destConfigEncrypted,
          }),
          // 5 min per batch. Observed worst-case TEE batch duration is ~130s;
          // the timeout must comfortably exceed it, otherwise an in-flight batch
          // gets aborted client-side and counted as failed even though the TEE
          // worker completes it (double-counting race).
          signal: AbortSignal.timeout(300_000),
        });

        if (!response.ok) {
          const text = await response.text();

          // Handle 401 specifically (token expired or invalid TEE auth)
          if (response.status === 401) {
            await this.migrationService.updateProgress(migrationId, 0, cids.length, cids);
            await this.migrationRepo.update(migrationId, { status: 'paused' });
            this.logger.warn(`Migration ${migrationId} paused due to TEE auth failure (401)`);
            return;
          }

          throw new Error(`TEE migration failed: ${response.status} ${text}`);
        }

        const result = (await response.json()) as {
          succeeded?: string[];
          failed?: string[];
        };

        await this.migrationService.updateProgress(
          migrationId,
          result.succeeded?.length ?? 0,
          result.failed?.length ?? 0,
          result.failed
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.logger.error(`Migration ${migrationId} batch error at offset ${i}: ${message}`);
        await this.migrationService.updateProgress(migrationId, 0, cids.length, cids);
      }
    }

    // Mark complete if still running
    const final = await this.migrationRepo.findOneOrFail({
      where: { id: migrationId },
    });
    if (final.status === 'running') {
      await this.migrationRepo.update(migrationId, {
        status: 'completed',
        completedAt: new Date(),
      });
      this.logger.log(`Migration ${migrationId} completed`);
    }
  }
}
