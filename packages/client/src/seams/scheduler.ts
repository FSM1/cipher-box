/**
 * `Scheduler` — wall clock and delays via worker timers
 * (blueprint/web-client.md seam table).
 *
 * The engine is the only source of time: `now` feeds core's pure functions,
 * `sleep` backs the poll cadence and re-PUT job. Background throttling of
 * worker timers is tolerated by design — coarse timers still fire, and every
 * wake-relevant transition also emits a refresh hint. Background-task
 * execution (`spawn`) is engine-side (WASM `spawn_local`), so it is not part of
 * this JS seam.
 */

import type { SchedulerSeam } from './types.js';

export class WorkerScheduler implements SchedulerSeam {
  now(): number {
    return Date.now();
  }

  sleep(durationMs: number): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, durationMs);
    });
  }
}
