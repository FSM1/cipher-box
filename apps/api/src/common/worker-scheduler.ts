import { Injectable, Logger } from '@nestjs/common';

/**
 * A unit of periodic background work. The scheduler owns the cadence; the task
 * owns one sweep. Deliberately capability-free so it is reusable: the
 * republisher's inventory walk is the first implementer, and the dormant-mailbox
 * scheduled sweep (#667) builds its scheduling on this same seam.
 *
 * `runOnce` MUST resolve/reject on its own — the scheduler never times it out —
 * and MUST NOT assume it runs alone: the scheduler skips a tick while the
 * previous sweep is still in flight, but a task should still be idempotent.
 */
export interface PeriodicTask {
  /** Stable label for logs/metrics (bounded cardinality). */
  readonly taskName: string;
  /** Cadence between sweeps, in ms. Injected — never read from a clock here. */
  readonly intervalMs: number;
  runOnce(): Promise<void>;
}

/**
 * Drives {@link PeriodicTask}s on their cadence. The one stateful loop shared by
 * every in-process worker (blueprint/api.md: in-process, worker-shaped, cleanly
 * extractable), so a future extraction moves this seam and its implementers
 * together. Production uses real timers; tests substitute a manual scheduler and
 * a fake clock so cadence and long-horizon timelines run in virtual time.
 */
@Injectable()
export abstract class WorkerScheduler {
  abstract register(task: PeriodicTask): void;
  abstract start(): void;
  abstract stop(): Promise<void>;
}

interface ScheduledEntry {
  task: PeriodicTask;
  handle?: ReturnType<typeof setInterval>;
  running: boolean;
}

/**
 * Real-timer scheduler. Each task fires on a `setInterval` at its own cadence;
 * a per-task in-flight flag drops overlapping ticks (a slow sweep never stacks),
 * and a thrown sweep is caught and logged so one failure never kills the loop.
 * `stop` clears every timer and awaits in-flight sweeps.
 */
@Injectable()
export class TimerWorkerScheduler extends WorkerScheduler {
  private readonly logger = new Logger(WorkerScheduler.name);
  private readonly entries: ScheduledEntry[] = [];
  private readonly inFlight = new Set<Promise<void>>();
  private started = false;

  register(task: PeriodicTask): void {
    if (this.started) {
      throw new Error('WorkerScheduler.register must be called before start');
    }
    this.entries.push({ task, running: false });
  }

  start(): void {
    if (this.started) {
      return;
    }
    this.started = true;
    for (const entry of this.entries) {
      entry.handle = setInterval(() => this.tick(entry), entry.task.intervalMs);
      // Don't keep the event loop alive solely for the sweep timer.
      entry.handle.unref?.();
    }
  }

  async stop(): Promise<void> {
    for (const entry of this.entries) {
      if (entry.handle) {
        clearInterval(entry.handle);
        entry.handle = undefined;
      }
    }
    this.started = false;
    await Promise.allSettled([...this.inFlight]);
  }

  private tick(entry: ScheduledEntry): void {
    if (entry.running) {
      // Previous sweep still in flight — drop this tick rather than stack.
      return;
    }
    entry.running = true;
    const run = entry.task
      .runOnce()
      .catch((error: unknown) => {
        // A failed sweep is logged and swallowed: the loop must survive it.
        this.logger.warn(`${entry.task.taskName} sweep failed: ${String(error)}`);
      })
      .finally(() => {
        entry.running = false;
        this.inFlight.delete(run);
      });
    this.inFlight.add(run);
  }
}
