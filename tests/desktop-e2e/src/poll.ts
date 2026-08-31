/**
 * The only wait this suite has. blueprint/testing.md fixes the law: no sleeps
 * anywhere, so every wait re-reads a real signal and stops on a deadline.
 */

/** The clock and the delay, injected so the unit suite needs no real time. */
export interface PollClock {
  now(): number;
  wait(ms: number): Promise<void>;
}

export const REAL_CLOCK: PollClock = {
  now: () => Date.now(),
  wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

export interface PollOptions {
  /** What the wait proves. It leads the timeout message. */
  what: string;
  timeoutMs: number;
  intervalMs: number;
  clock?: PollClock;
}

/**
 * A wait that ran out. It carries the last observed value, so a report names
 * the state the suite reached rather than only that time ran out.
 */
export class PollTimeout extends Error {
  readonly last: unknown;
  readonly attempts: number;

  constructor(what: string, last: unknown, attempts: number, timeoutMs: number) {
    super(
      `${what} did not happen within ${timeoutMs}ms over ${attempts} reads; ` +
        `the last value was ${describe(last)}`
    );
    this.name = 'PollTimeout';
    this.last = last;
    this.attempts = attempts;
  }
}

/**
 * Reads `probe` until `accept` returns true, or until the deadline.
 *
 * A throw from either function ends the wait at once: a broken probe is a
 * defect, and a retry only hides it behind the timeout.
 */
export async function poll<T, Narrowed extends T>(
  probe: () => T | Promise<T>,
  accept: (value: T) => value is Narrowed,
  options: PollOptions
): Promise<Narrowed>;
export async function poll<T>(
  probe: () => T | Promise<T>,
  accept: (value: T) => boolean,
  options: PollOptions
): Promise<T>;
export async function poll<T>(
  probe: () => T | Promise<T>,
  accept: (value: T) => boolean,
  options: PollOptions
): Promise<T> {
  const clock = options.clock ?? REAL_CLOCK;
  const deadline = clock.now() + options.timeoutMs;
  let last: unknown;
  let attempts = 0;

  for (;;) {
    const value = await probe();
    attempts += 1;
    last = value;
    if (accept(value)) return value;
    if (clock.now() >= deadline) {
      throw new PollTimeout(options.what, last, attempts, options.timeoutMs);
    }
    await clock.wait(options.intervalMs);
  }
}

function describe(value: unknown): string {
  if (value === undefined) return 'undefined';
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}
