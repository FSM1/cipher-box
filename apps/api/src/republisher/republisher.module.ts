import { Module, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { buildJwtOptions } from '../auth/auth.module';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { TimerWorkerScheduler, WorkerScheduler } from '../common/worker-scheduler';
import { OpsModule } from '../ops/ops.module';
import { NameInventory } from '../registry/entities/name-inventory.entity';
import { RecordCache } from './entities/record-cache.entity';
import { MinimalIpnsSequenceReader, RecordSequenceReader } from './record-sequence-reader';
import { RecordTransport, RoutingV1RecordTransport } from './record-transport';
import { RecoveryController } from './recovery.controller';
import { LoggingRepublisherAlerter, RepublisherAlerter } from './republisher.alerter';
import { RepublisherTask } from './republisher.task';
import { RecordCacheService } from './services/record-cache.service';

/** Disabled tokens for a default-on flag; case-insensitive so `False`/`0`/`OFF` all count. */
const DISABLED_TOKENS = new Set(['false', '0', 'no', 'off']);

/** A default-on env flag is disabled only by an explicit falsey token; unset stays on. */
export function isDisabled(raw: unknown): boolean {
  return DISABLED_TOKENS.has(String(raw).trim().toLowerCase());
}

/**
 * The republisher slice (blueprint/api.md, Republisher module and recovery): the
 * in-process, worker-shaped, cleanly extractable liveness backstop and its
 * recovery endpoint. It owns the non-canonical record cache, the inventory walk
 * on a ~12h cadence, and the authenticated recovery fetch. The name inventory is
 * read-only here (the registry slice owns writes). Every side effect — the
 * network transport, the sequence read, alerting, and the scheduler — is a seam,
 * so the walk is deterministic under test and the module extracts cleanly.
 *
 * The scheduler and its {@link RepublisherTask} are wired here, but the loop is
 * generic. The {@link WorkerScheduler} provider is scoped to this module, not a
 * shared instance — when the dormant-mailbox scheduled sweep (#667) lands, one
 * shared loop means exporting this provider (or hoisting it into a shared
 * module) and registering the mailbox PeriodicTask on it, not binding a second.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([RecordCache, NameInventory]),
    OpsModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [RecoveryController],
  providers: [
    RecordCacheService,
    RepublisherTask,
    JwtAuthGuard,
    { provide: WorkerScheduler, useClass: TimerWorkerScheduler },
    { provide: RecordTransport, useClass: RoutingV1RecordTransport },
    { provide: RecordSequenceReader, useClass: MinimalIpnsSequenceReader },
    { provide: RepublisherAlerter, useClass: LoggingRepublisherAlerter },
  ],
})
export class RepublisherModule implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    private readonly scheduler: WorkerScheduler,
    private readonly task: RepublisherTask,
    private readonly configService: ConfigService
  ) {}

  onApplicationBootstrap(): void {
    // Opt-out for deployments that run the republisher out of process (or none),
    // defaulting on. Absent, the loop is a no-op cost — an unref'd 12h timer.
    if (isDisabled(this.configService.get('REPUBLISHER_ENABLED'))) {
      return;
    }
    this.scheduler.register(this.task);
    this.scheduler.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.scheduler.stop();
  }
}
