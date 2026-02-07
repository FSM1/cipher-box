import { Module, Logger, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { Queue } from 'bullmq';
import { IpnsRepublishSchedule } from './republish-schedule.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { TeeModule } from '../tee/tee.module';
import { RepublishService } from './republish.service';
import { RepublishProcessor } from './republish.processor';
import { RepublishHealthController } from './republish-health.controller';

@Module({
  imports: [
    BullModule.registerQueue({ name: 'republish' }),
    TypeOrmModule.forFeature([IpnsRepublishSchedule, FolderIpns]),
    TeeModule,
    ConfigModule,
  ],
  providers: [RepublishService, RepublishProcessor],
  controllers: [RepublishHealthController],
  exports: [RepublishService],
})
export class RepublishModule implements OnModuleInit {
  private readonly logger = new Logger(RepublishModule.name);

  constructor(@InjectQueue('republish') private readonly queue: Queue) {}

  async onModuleInit(): Promise<void> {
    try {
      // Create repeating job scheduler: every 6 hours
      await this.queue.upsertJobScheduler(
        'republish-cron',
        {
          pattern: '0 */6 * * *', // Every 6 hours: 00:00, 06:00, 12:00, 18:00
        },
        {
          name: 'republish-batch',
        }
      );
      this.logger.log('Republish cron scheduler registered: every 6 hours (0 */6 * * *)');
    } catch (error) {
      // Redis may be unavailable during development
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Failed to register republish cron scheduler (non-fatal): ${message}`);
    }
  }
}
