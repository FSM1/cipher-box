/**
 * The soak's refresh: a refresh that answers overdue is sent again until it
 * lands or the step budget runs out. Every other refusal ends the step.
 */

import { ControlRefusal, REFRESH_OVERDUE } from '../control';
import { REAL_CLOCK, type PollClock } from '../poll';

export interface OverdueRetry {
  /** The instance name, which leads each retry line. */
  name: string;
  /** When the step budget ends, on `clock`. */
  untilMs: number;
  /** The pause before a retry. A refresh filed during an overdue pass is overdue at once. */
  intervalMs: number;
  log: (line: string) => void;
  clock?: PollClock;
}

export function isOverdue(error: unknown): error is ControlRefusal {
  return (
    error instanceof ControlRefusal && error.verb === 'refresh' && error.refusal === REFRESH_OVERDUE
  );
}

/** Sends `refresh` until it lands. Past `untilMs`, the last overdue refusal is the failure. */
export async function refreshPastOverdue(
  refresh: () => Promise<void>,
  options: OverdueRetry
): Promise<void> {
  const clock = options.clock ?? REAL_CLOCK;
  const started = clock.now();
  for (let attempt = 1; ; attempt += 1) {
    const sent = clock.now();
    try {
      await refresh();
      return;
    } catch (error) {
      if (!isOverdue(error)) throw error;
      const now = clock.now();
      const left = options.untilMs - now;
      options.log(
        `  ${options.name}: refresh ${attempt} was overdue after ${now - sent}ms ` +
          `(${now - started}ms since the first)` +
          (left > options.intervalMs ? '; it retries\n' : '; the step budget is spent\n')
      );
      if (left <= options.intervalMs) throw error;
      await clock.wait(options.intervalMs);
    }
  }
}
