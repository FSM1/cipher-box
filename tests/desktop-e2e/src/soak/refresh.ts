/**
 * The soak's refresh: a refresh that answers overdue is sent again until it
 * lands or the step budget runs out. Every other refusal ends the step.
 */

import { ControlRefusal, REFRESH_OVERDUE } from '../control';
import { REAL_CLOCK, type PollClock } from '../poll';

export interface OverdueRetry {
  /** The instance name, which leads each log line. */
  name: string;
  /** When the step budget ends, on `clock`. */
  untilMs: number;
  /**
   * The pause before a retry. The engine answers each refresh filed during an
   * overdue pass overdue at once, until that tick ends: one tick is the pace.
   */
  waitMs: number;
  /** How long one retry can take before the engine answers it overdue. */
  refreshDeadlineMs: number;
  log: (line: string) => void;
  clock?: PollClock;
}

function isOverdue(error: unknown): error is ControlRefusal {
  return (
    error instanceof ControlRefusal && error.verb === 'refresh' && error.refusal === REFRESH_OVERDUE
  );
}

/**
 * Sends `refresh` until it lands. A retry starts only while a whole refresh
 * deadline is left, and a retry that lands past `untilMs` does not count: the
 * failure is then the last overdue refusal.
 */
export async function refreshPastOverdue(
  refresh: () => Promise<void>,
  options: OverdueRetry
): Promise<void> {
  const { name, untilMs, waitMs, refreshDeadlineMs, log } = options;
  const clock = options.clock ?? REAL_CLOCK;
  const started = clock.now();
  let overdue: ControlRefusal | undefined;
  const spent = (attempts: number, last: string): ControlRefusal => {
    log(
      `  ${name}: refresh ${last} on attempt ${attempts}, ${clock.now() - started}ms ` +
        `after the first; the step budget is spent\n`
    );
    return overdue as ControlRefusal;
  };

  for (let attempt = 1; ; attempt += 1) {
    try {
      await refresh();
    } catch (error) {
      if (!isOverdue(error)) throw error;
      if (!overdue) {
        log(
          `  ${name}: refresh 1 was overdue after ${clock.now() - started}ms; ` +
            `it retries every ${waitMs}ms\n`
        );
      }
      overdue = error;
      if (untilMs - clock.now() <= waitMs + refreshDeadlineMs) throw spent(attempt, 'was overdue');
      await clock.wait(waitMs);
      if (untilMs - clock.now() <= refreshDeadlineMs) throw spent(attempt, 'was overdue');
      continue;
    }
    if (!overdue) return;
    if (clock.now() > untilMs) throw spent(attempt, 'landed late');
    log(
      `  ${name}: refresh landed on attempt ${attempt}, ${clock.now() - started}ms after the first\n`
    );
    return;
  }
}
