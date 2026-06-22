import { Module, Logger, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { Queue } from 'bullmq';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IpfsProviderModule } from '../providers';
import { PendingUnpinProcessor } from './pending-unpin.processor';

@Module({
  imports: [
    BullModule.registerQueue({ name: 'pending-unpins' }),
    TypeOrmModule.forFeature([PendingUnpin, PinnedCid]),
    ConfigModule,
    IpfsProviderModule,
  ],
  providers: [PendingUnpinProcessor],
})
export class PendingUnpinModule implements OnModuleInit {
  private readonly logger = new Logger(PendingUnpinModule.name);

  constructor(@InjectQueue('pending-unpins') private readonly queue: Queue) {}

  async onModuleInit(): Promise<void> {
    try {
      // Drain worker: retry pending_unpins every 5 minutes (D-05)
      await this.queue.upsertJobScheduler(
        'pending-unpins-drain',
        { pattern: '*/5 * * * *' },
        { name: 'drain-pending-unpins' }
      );

      // Drift report: read-only Kubo vs DB diff every hour (D-06)
      await this.queue.upsertJobScheduler(
        'pin-drift-report',
        { pattern: '0 * * * *' },
        { name: 'drift-report' }
      );

      this.logger.log(
        'PendingUnpin schedulers registered: drain every 5 min, drift report every hour'
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // Outside production, Redis may be unavailable (local dev / tests) — non-fatal.
      // In production, swallowing this would leave drain/drift jobs unregistered and
      // pending_unpins stuck with no recovery, so fail fast on startup instead.
      if (process.env.NODE_ENV === 'production') {
        this.logger.error(`Failed to register PendingUnpin schedulers: ${message}`);
        throw error;
      }
      this.logger.warn(`Failed to register PendingUnpin schedulers (non-fatal): ${message}`);
    }
  }
}
