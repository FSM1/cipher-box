import { Injectable, Module, OnModuleInit } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SchedulerModule } from './scheduler.module';
import { PeriodicTask, WorkerScheduler } from './worker-scheduler';

class CountingTask implements PeriodicTask {
  runs = 0;
  constructor(
    readonly taskName: string,
    readonly intervalMs: number
  ) {}
  async runOnce(): Promise<void> {
    this.runs += 1;
  }
}

/**
 * A feature module that, like the real republisher/mailbox slices, registers its
 * task in `onModuleInit` on the SHARED scheduler it imports — never starting the
 * loop itself.
 */
function consumerModule(task: CountingTask) {
  @Injectable()
  class Registrar implements OnModuleInit {
    constructor(private readonly scheduler: WorkerScheduler) {}
    onModuleInit(): void {
      this.scheduler.register(task);
    }
  }

  @Module({ imports: [SchedulerModule], providers: [Registrar] })
  class ConsumerModule {}

  return ConsumerModule;
}

describe('SchedulerModule shared loop', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('starts tasks that multiple consumer modules register in onModuleInit on ONE shared scheduler', async () => {
    const a = new CountingTask('a', 1000);
    const b = new CountingTask('b', 1000);
    const ModuleA = consumerModule(a);
    const ModuleB = consumerModule(b);

    const moduleRef = await Test.createTestingModule({
      imports: [ModuleA, ModuleB],
    }).compile();
    const app = moduleRef.createNestApplication();

    // Both consumers import SchedulerModule; a single shared instance backs both.
    const viaA = app.select(ModuleA).get(WorkerScheduler, { strict: false });
    const viaB = app.select(ModuleB).get(WorkerScheduler, { strict: false });
    expect(viaA).toBe(viaB);

    // init() runs every onModuleInit (both registrations) before the module's
    // onApplicationBootstrap start() — so the single start schedules both tasks.
    await app.init();

    await vi.advanceTimersByTimeAsync(1000);
    expect(a.runs).toBe(1);
    expect(b.runs).toBe(1);

    await app.close();

    // stop() cleared the timers: no further ticks fire.
    await vi.advanceTimersByTimeAsync(5000);
    expect(a.runs).toBe(1);
    expect(b.runs).toBe(1);
  });
});
