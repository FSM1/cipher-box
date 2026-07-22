import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { buildJwtOptions } from '../auth/auth.module';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SchedulerModule } from '../common/scheduler.module';
import { WorkerScheduler } from '../common/worker-scheduler';
import { OpsModule } from '../ops/ops.module';
import { NameInventory } from '../registry/entities/name-inventory.entity';
import { RecordCache } from './entities/record-cache.entity';
import { MinimalIpnsSequenceReader, RecordSequenceReader } from './record-sequence-reader';
import { RecordTransport, RoutingV1RecordTransport } from './record-transport';
import { RecoveryController } from './recovery.controller';
import { LoggingRepublisherAlerter, RepublisherAlerter } from './republisher.alerter';
import { RepublisherTask } from './republisher.task';
import { RecordCacheService } from './services/record-cache.service';

// Re-exported so the one implementation lives in common; existing importers keep
// resolving `isDisabled` from this module.
export { isDisabled } from '../common/env-flag';
import { isDisabled } from '../common/env-flag';

/**
 * The republisher slice (blueprint/api.md, Republisher module and recovery): the
 * in-process, worker-shaped, cleanly extractable liveness backstop and its
 * recovery endpoint. It owns the non-canonical record cache, the inventory walk
 * on a ~12h cadence, and the authenticated recovery fetch. The name inventory is
 * read-only here (the registry slice owns writes). Every side effect — the
 * network transport, the sequence read, alerting, and the scheduler — is a seam,
 * so the walk is deterministic under test and the module extracts cleanly.
 *
 * The {@link RepublisherTask} registers on the shared {@link SchedulerModule}
 * loop, not a scheduler bound here — one loop carries every PeriodicTask (the
 * dormant-mailbox sweep, #667, is the sibling). Registration happens in
 * `onModuleInit`; the shared module owns `start()`/`stop()`, so the loop runs
 * even when this slice opts out.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([RecordCache, NameInventory]),
    OpsModule,
    SchedulerModule,
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
    { provide: RecordTransport, useClass: RoutingV1RecordTransport },
    { provide: RecordSequenceReader, useClass: MinimalIpnsSequenceReader },
    { provide: RepublisherAlerter, useClass: LoggingRepublisherAlerter },
  ],
})
export class RepublisherModule implements OnModuleInit {
  constructor(
    private readonly scheduler: WorkerScheduler,
    private readonly task: RepublisherTask,
    private readonly configService: ConfigService
  ) {}

  onModuleInit(): void {
    // Opt-out for deployments that run the republisher out of process (or none),
    // defaulting on. Absent, the loop is a no-op cost — an unref'd 12h timer.
    if (isDisabled(this.configService.get('REPUBLISHER_ENABLED'))) {
      return;
    }
    this.scheduler.register(this.task);
  }
}
