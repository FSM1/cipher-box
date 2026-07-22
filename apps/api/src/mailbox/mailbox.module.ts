import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { buildJwtOptions } from '../auth/auth.module';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { isDisabled } from '../common/env-flag';
import { SchedulerModule } from '../common/scheduler.module';
import { WorkerScheduler } from '../common/worker-scheduler';
import { IdentityService } from '../auth/services/identity.service';
import { MailboxController } from './mailbox.controller';
import { MailboxMessage } from './entities/mailbox-message.entity';
import { MailboxService } from './services/mailbox.service';
import { MailboxSweepTask } from './tasks/mailbox-sweep.task';

/**
 * The mailbox slice (blueprint/api.md, Mailbox). Reads the users table for
 * the recipient-existence oracle and provides its own stateless
 * IdentityService for publicKey normalization. Route auth reuses the auth
 * slice's JwtAuthGuard and JWT configuration.
 *
 * The scheduled dormant-mailbox TTL sweep (#667) registers on the shared
 * {@link SchedulerModule} loop in `onModuleInit` — independent of per-recipient
 * activity and of the republisher's own opt-out, so a dormant mailbox's expired
 * rows are still swept.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([MailboxMessage, User]),
    SchedulerModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [MailboxController],
  providers: [MailboxService, IdentityService, JwtAuthGuard, MailboxSweepTask],
})
export class MailboxModule implements OnModuleInit {
  constructor(
    private readonly scheduler: WorkerScheduler,
    private readonly sweepTask: MailboxSweepTask,
    private readonly configService: ConfigService
  ) {}

  onModuleInit(): void {
    // Opt-out (default on) for deployments that run the sweep out of process or
    // pin it to a single instance. Absent, the loop is an unref'd 12h timer.
    if (isDisabled(this.configService.get('MAILBOX_SWEEP_ENABLED'))) {
      return;
    }
    this.scheduler.register(this.sweepTask);
  }
}
