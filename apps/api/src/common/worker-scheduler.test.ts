import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PeriodicTask, TimerWorkerScheduler } from './worker-scheduler';

/** A task whose runOnce is fully controlled by the test. */
class ControllableTask implements PeriodicTask {
  runs = 0;
  private resolvers: Array<() => void> = [];

  constructor(
    readonly taskName: string,
    readonly intervalMs: number
  ) {}

  runOnce(): Promise<void> {
    this.runs += 1;
    return new Promise<void>((resolve) => this.resolvers.push(resolve));
  }

  /** Complete the oldest in-flight sweep. */
  completeOldest(): void {
    this.resolvers.shift()?.();
  }

  /** Complete every in-flight sweep so a graceful stop() can drain. */
  completeAll(): void {
    while (this.resolvers.length) {
      this.resolvers.shift()?.();
    }
  }
}

describe('TimerWorkerScheduler', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('fires each task once per interval', async () => {
    const scheduler = new TimerWorkerScheduler();
    const task = new ControllableTask('walk', 1000);
    scheduler.register(task);
    scheduler.start();

    expect(task.runs).toBe(0);
    await vi.advanceTimersByTimeAsync(1000);
    expect(task.runs).toBe(1);
    task.completeOldest();
    await vi.advanceTimersByTimeAsync(1000);
    expect(task.runs).toBe(2);

    task.completeAll();
    await scheduler.stop();
  });

  it('drops overlapping ticks while a sweep is still in flight', async () => {
    const scheduler = new TimerWorkerScheduler();
    const task = new ControllableTask('walk', 1000);
    scheduler.register(task);
    scheduler.start();

    // First tick starts a sweep that never completes; the next two ticks are
    // dropped rather than stacked.
    await vi.advanceTimersByTimeAsync(3000);
    expect(task.runs).toBe(1);

    // Once the sweep completes, the next tick runs.
    task.completeOldest();
    await vi.advanceTimersByTimeAsync(1000);
    expect(task.runs).toBe(2);

    task.completeAll();
    await scheduler.stop();
  });

  it('keeps the loop alive after a sweep throws', async () => {
    const scheduler = new TimerWorkerScheduler();
    let calls = 0;
    const task: PeriodicTask = {
      taskName: 'flaky',
      intervalMs: 1000,
      runOnce: async () => {
        calls += 1;
        throw new Error('boom');
      },
    };
    scheduler.register(task);
    scheduler.start();

    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls).toBe(2); // the first throw did not kill the timer

    await scheduler.stop();
  });

  it('runs independent tasks on their own cadences', async () => {
    const scheduler = new TimerWorkerScheduler();
    const fast = new ControllableTask('fast', 500);
    const slow = new ControllableTask('slow', 2000);
    scheduler.register(fast);
    scheduler.register(slow);
    scheduler.start();

    // Complete each fast sweep as it starts so the fast cadence keeps firing;
    // the slow task fires exactly once over the same window.
    for (let i = 0; i < 4; i += 1) {
      await vi.advanceTimersByTimeAsync(500);
      fast.completeOldest();
    }
    expect(fast.runs).toBe(4);
    expect(slow.runs).toBe(1);

    fast.completeAll();
    slow.completeAll();
    await scheduler.stop();
  });

  it('refuses registration after start', () => {
    const scheduler = new TimerWorkerScheduler();
    scheduler.start();
    expect(() => scheduler.register(new ControllableTask('late', 1000))).toThrow();
  });

  it('stop clears timers so no further ticks fire', async () => {
    const scheduler = new TimerWorkerScheduler();
    const task = new ControllableTask('walk', 1000);
    scheduler.register(task);
    scheduler.start();
    await scheduler.stop();

    await vi.advanceTimersByTimeAsync(5000);
    expect(task.runs).toBe(0);
  });
});
