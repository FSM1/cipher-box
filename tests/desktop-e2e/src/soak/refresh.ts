/**
 * The soak's refresh: a refresh that answers overdue is sent again until it
 * lands or the step budget runs out. Every other refusal ends the step.
 */

import { ControlRefusal, REFRESH_OVERDUE } from '../control';
import { REAL_CLOCK, type PollClock } from '../poll';

/**
 * How long before `untilMs` an unanswered refresh gives up, so the probe that
 * sent it fails before the poll alarm of its step takes the mount away.
 */
const ANSWER_MARGIN_MS = 1_000;

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
  /** `SyncTimingProfile.refreshDeadlineMs`. */
  refreshDeadlineMs: number;
  log: (line: string) => void;
  clock?: PollClock;
}

function isOverdue(error: unknown): error is ControlRefusal {
  return (
    error instanceof ControlRefusal && error.verb === 'refresh' && error.refusal === REFRESH_OVERDUE
  );
}

const UNANSWERED = Symbol('unanswered');

/**
 * Sends `refresh` until it lands. A retry starts only while a wait and a
 * refresh deadline are left. A refresh with no answer by `untilMs` less the
 * margin ends the step: with the last overdue refusal, or with no answer.
 */
export async function refreshPastOverdue(
  refresh: () => Promise<void>,
  options: OverdueRetry
): Promise<void> {
  const { name, untilMs, waitMs, refreshDeadlineMs, log } = options;
  const clock = options.clock ?? REAL_CLOCK;
  const started = clock.now();
  let overdue: ControlRefusal | undefined;

  const spent = (attempts: number, last: 'was overdue' | 'got no answer'): Error => {
    log(
      `  ${name}: refresh ${last} on attempt ${attempts}, ${clock.now() - started}ms ` +
        `after the first; the step budget is spent\n`
    );
    return overdue ?? new Error(`${name}: the refresh got no answer within the step budget`);
  };

  /** The overdue refusal a refresh answered, `undefined` once it lands. */
  const send = async (attempts: number): Promise<ControlRefusal | undefined> => {
    const alarm = clock.alarm(Math.max(0, untilMs - ANSWER_MARGIN_MS - clock.now()));
    // A refresh the alarm outran settles on its own socket timeout, unread.
    const answer = refresh().then(
      () => undefined,
      (error: unknown) => {
        if (isOverdue(error)) return error;
        throw error;
      }
    );
    try {
      const outcome = await Promise.race([
        answer,
        alarm.expired.then((): typeof UNANSWERED => UNANSWERED),
      ]);
      if (outcome === UNANSWERED) throw spent(attempts, 'got no answer');
      return outcome;
    } finally {
      alarm.cancel();
    }
  };

  const first = await send(1);
  if (!first) return;
  overdue = first;
  log(
    `  ${name}: refresh 1 was overdue after ${clock.now() - started}ms; it retries every ${waitMs}ms\n`
  );

  for (let attempts = 1; ; ) {
    if (untilMs - clock.now() <= waitMs + refreshDeadlineMs) throw spent(attempts, 'was overdue');
    await clock.wait(waitMs);
    if (untilMs - clock.now() <= refreshDeadlineMs) throw spent(attempts, 'was overdue');
    attempts += 1;
    const next = await send(attempts);
    if (next) {
      overdue = next;
      continue;
    }
    log(
      `  ${name}: refresh landed on attempt ${attempts}, ${clock.now() - started}ms after the first\n`
    );
    return;
  }
}
