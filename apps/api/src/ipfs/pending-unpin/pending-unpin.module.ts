import { Module, Logger, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IPFS_PROVIDER, LocalProvider } from '../providers';
import { PendingUnpinProcessor } from './pending-unpin.processor';

@Module({
  imports: [
    BullModule.registerQueue({ name: 'pending-unpins' }),
    TypeOrmModule.forFeature([PendingUnpin, PinnedCid]),
    ConfigModule,
  ],
  providers: [
    PendingUnpinProcessor,
    {
      // Provide IPFS_PROVIDER locally to avoid importing IpfsModule
      // (IpfsModule imports VaultModule — circular if pending-unpin imports it)
      provide: IPFS_PROVIDER,
      useFactory: (configService: ConfigService) => {
        const apiUrl = configService.get<string>('IPFS_LOCAL_API_URL', 'http://localhost:5001');
        const gatewayUrl = configService.get<string>(
          'IPFS_LOCAL_GATEWAY_URL',
          'http://localhost:8080'
        );
        return new LocalProvider(apiUrl, gatewayUrl);
      },
      inject: [ConfigService],
    },
  ],
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
      // Redis may be unavailable during development; non-fatal
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Failed to register PendingUnpin schedulers (non-fatal): ${message}`);
    }
  }
}
