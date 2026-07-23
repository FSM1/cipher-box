import { Module, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { TimerWorkerScheduler, WorkerScheduler } from './worker-scheduler';

/**
 * The one shared worker loop (blueprint/api.md: in-process, worker-shaped,
 * cleanly extractable). A single {@link WorkerScheduler} instance is provided and
 * exported here, so every feature module that owns a {@link PeriodicTask} — the
 * republisher walk, the dormant-mailbox sweep (#667) — registers on the SAME loop
 * rather than binding a second scheduler.
 *
 * Lifecycle is owned here, not by the task modules: feature modules register
 * their task in `onModuleInit`, and this module calls `start()` in
 * `onApplicationBootstrap`. Nest runs EVERY `onModuleInit` before ANY
 * `onApplicationBootstrap`, so all registrations land before the single start —
 * the scheduler's register-before-start contract holds regardless of module
 * topology, and no task's cadence is coupled to another module's opt-out flag.
 */
@Module({
  providers: [{ provide: WorkerScheduler, useClass: TimerWorkerScheduler }],
  exports: [WorkerScheduler],
})
export class SchedulerModule implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(private readonly scheduler: WorkerScheduler) {}

  onApplicationBootstrap(): void {
    this.scheduler.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.scheduler.stop();
  }
}
