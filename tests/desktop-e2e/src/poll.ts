/**
 * The only wait this suite has. blueprint/testing.md fixes the law: no sleeps
 * anywhere, so every wait re-reads a real signal and stops on a deadline.
 */

/** A timer that fires once. `expired` never rejects, and `cancel` is safe after it fired. */
export interface Alarm {
  readonly expired: Promise<void>;
  cancel(): void;
}

/** The clock, the delay and the alarm, injected so the unit suite needs no real time. */
export interface PollClock {
  now(): number;
  wait(ms: number): Promise<void>;
  alarm(ms: number): Alarm;
}

export const REAL_CLOCK: PollClock = {
  now: () => Date.now(),
  wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  alarm(ms) {
    let timer: NodeJS.Timeout | undefined;
    const expired = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, ms);
      // A read that wedged holds the run open by itself. This timer must not
      // hold it open past the wait it bounds.
      timer.unref();
    });
    return { expired, cancel: () => clearTimeout(timer) };
  },
};

export interface PollOptions {
  /** What the wait proves. It leads the timeout message. */
  what: string;
  timeoutMs: number;
  intervalMs: number;
  clock?: PollClock;
  /**
   * Frees what a read that wedged holds, before the wait reports it.
   *
   * A kernel call on a mount carries no timeout of its own, so only the mount
   * going away returns it: a wait that reads a mount gives its instance here.
   * A deadline that every read answered holds nothing, and calls none of this.
   * The report waits for the release, bounded by `RELEASE_WITHIN_MS`.
   */
  release?: () => Promise<unknown>;
}

/**
 * A wait that ran out. It carries the last observed value, so a report names
 * the state the suite reached rather than only that time ran out.
 */
export class PollTimeout extends Error {
  readonly last: unknown;
  readonly attempts: number;
  /** Whether a read was still in flight at the deadline. */
  readonly stalled: boolean;

  constructor(what: string, last: unknown, attempts: number, timeoutMs: number, stalled: boolean) {
    super(
      `${what} did not happen within ${timeoutMs}ms on ${process.platform}` +
        (stalled ? `: read ${attempts + 1} did not answer` : ` over ${attempts} reads`) +
        `; the last value was ${describe(last)}`
    );
    this.name = 'PollTimeout';
    this.last = last;
    this.attempts = attempts;
    this.stalled = stalled;
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
  // One alarm bounds the read itself, so a read that never answers reports this
  // wait rather than the job timeout. The loop below cannot bound it: the loop
  // reaches its own deadline only after the read it is in returns.
  const alarm = clock.alarm(options.timeoutMs);
  let last: unknown;
  let attempts = 0;
  let reading = false;

  // The deadline latches one timeout, which every path then reports. The loop
  // reads it on both sides of a read, so the deadline starts no further read
  // and accepts no value that landed after it.
  let expired: PollTimeout | undefined;

  const reads = (async (): Promise<T> => {
    for (;;) {
      if (expired) throw expired;
      reading = true;
      const value = await probe();
      reading = false;
      if (expired) throw expired;
      attempts += 1;
      last = value;
      if (accept(value)) return value;
      const remaining = deadline - clock.now();
      if (remaining <= 0) {
        throw new PollTimeout(options.what, last, attempts, options.timeoutMs, false);
      }
      // Never sleep past the deadline: a wait longer than what is left would
      // report the timeout late, and a caller reads that delay as a slow signal.
      await clock.wait(Math.min(options.intervalMs, remaining));
    }
  })();

  try {
    return await Promise.race([
      reads,
      alarm.expired.then(async (): Promise<never> => {
        expired = new PollTimeout(options.what, last, attempts, options.timeoutMs, reading);
        if (reading) await freeWithin(clock, options.release);
        throw expired;
      }),
    ]);
  } finally {
    alarm.cancel();
  }
}

/**
 * How long a release is given. It is teardown, never a wait: a release that
 * hangs must not become the wait it was called to end.
 */
const RELEASE_WITHIN_MS = 30_000;

async function freeWithin(clock: PollClock, release: PollOptions['release']): Promise<void> {
  if (!release) return;
  const bound = clock.alarm(RELEASE_WITHIN_MS);
  try {
    await Promise.race([
      Promise.resolve()
        .then(release)
        .catch(() => undefined),
      bound.expired,
    ]);
  } finally {
    bound.cancel();
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
