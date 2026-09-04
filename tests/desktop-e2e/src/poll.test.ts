import { describe, expect, it } from 'vitest';
import { poll, PollTimeout, REAL_CLOCK, type PollClock } from './poll';

/** A clock the test drives, so no unit test spends real time. */
function fakeClock(): PollClock & { elapsed(): number; cancelled(): number } {
  let millis = 0;
  let cancelled = 0;
  return {
    now: () => millis,
    wait: async (ms) => {
      millis += ms;
    },
    // The alarm fires on a real macrotask, and every other step of the wait
    // settles on a microtask: a read that answers always wins the race, and
    // only a read that never answers reaches the alarm.
    alarm: (ms) => {
      const due = millis + ms;
      let timer: NodeJS.Timeout | undefined;
      const expired = new Promise<void>((resolve) => {
        timer = setTimeout(() => {
          millis = Math.max(millis, due);
          resolve();
        }, 0);
      });
      return {
        expired,
        cancel: () => {
          cancelled += 1;
          clearTimeout(timer);
        },
      };
    },
    elapsed: () => millis,
    cancelled: () => cancelled,
  };
}

describe('poll', () => {
  it('returns the first value the predicate accepts', async () => {
    const clock = fakeClock();
    const seen = [1, 2, 3];
    let index = 0;

    const value = await poll(
      () => seen[index++],
      (n) => n === 3,
      {
        what: 'the third read',
        timeoutMs: 1000,
        intervalMs: 10,
        clock,
      }
    );

    expect(value).toBe(3);
    expect(index).toBe(3);
  });

  it('reads the signal again on every attempt', async () => {
    const clock = fakeClock();
    let reads = 0;

    await poll(
      () => {
        reads += 1;
        return reads;
      },
      (n) => n >= 4,
      { what: 'a fourth read', timeoutMs: 1000, intervalMs: 10, clock }
    );

    expect(reads).toBe(4);
  });

  it('accepts a value the first probe already satisfies with no wait', async () => {
    const clock = fakeClock();

    await poll(
      () => 'mounted',
      (state) => state === 'mounted',
      {
        what: 'a mounted state',
        timeoutMs: 1000,
        intervalMs: 10,
        clock,
      }
    );

    expect(clock.elapsed()).toBe(0);
  });

  it('reports the last value it observed when the deadline passes', async () => {
    const clock = fakeClock();

    const failure = await poll(
      () => ({ state: 'opening' }),
      () => false,
      {
        what: 'the mount to open',
        timeoutMs: 100,
        intervalMs: 25,
        clock,
      }
    ).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(PollTimeout);
    const timeout = failure as PollTimeout;
    expect(timeout.last).toEqual({ state: 'opening' });
    expect(timeout.message).toContain('the mount to open');
    expect(timeout.message).toContain('"state":"opening"');
    expect(timeout.attempts).toBeGreaterThan(1);
  });

  it('never waits past the deadline, whatever the interval asks for', async () => {
    const clock = fakeClock();

    await poll(
      () => 'opening',
      () => false,
      { what: 'the mount to open', timeoutMs: 100, intervalMs: 1000, clock }
    ).catch(() => undefined);

    expect(clock.elapsed()).toBe(100);
  });

  it('propagates a throw from the probe rather than a retry past it', async () => {
    const clock = fakeClock();
    let reads = 0;

    const failure = await poll(
      () => {
        reads += 1;
        throw new Error('the endpoint is unreachable');
      },
      () => true,
      { what: 'a status', timeoutMs: 1000, intervalMs: 10, clock }
    ).catch((error: unknown) => error);

    expect((failure as Error).message).toBe('the endpoint is unreachable');
    expect(reads).toBe(1);
  });

  it('propagates a throw from the predicate', async () => {
    const clock = fakeClock();

    const failure = await poll(
      () => 'refused',
      (state) => {
        if (state === 'refused')
          throw new Error('the mount refused; a refusal is never waited out');
        return false;
      },
      { what: 'a mount', timeoutMs: 1000, intervalMs: 10, clock }
    ).catch((error: unknown) => error);

    expect((failure as Error).message).toContain('a refusal is never waited out');
  });

  it('reports the deadline when a read never answers, and names that read', async () => {
    const clock = fakeClock();
    let reads = 0;

    const failure = await poll(
      (): Promise<{ state: string }> => {
        reads += 1;
        // The second read is the wedged mount: it never settles, and no
        // AbortSignal releases the kernel call underneath it.
        return reads === 1 ? Promise.resolve({ state: 'opening' }) : new Promise(() => {});
      },
      () => false,
      { what: 'the mount to serve a listing', timeoutMs: 100, intervalMs: 25, clock }
    ).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(PollTimeout);
    const timeout = failure as PollTimeout;
    expect(timeout.stalled).toBe(true);
    expect(timeout.attempts).toBe(1);
    expect(timeout.last).toEqual({ state: 'opening' });
    expect(timeout.message).toContain('the mount to serve a listing');
    expect(timeout.message).toContain('read 2 did not answer');
    expect(timeout.message).toContain(process.platform);
    expect(timeout.message).toContain('"state":"opening"');
    expect(clock.elapsed()).toBe(100);
  });

  it('frees what a read that never answers holds, before it reports', async () => {
    const clock = fakeClock();
    const order: string[] = [];

    const failure = await poll(
      () => new Promise<string>(() => {}),
      () => true,
      {
        what: 'the mount to answer',
        timeoutMs: 50,
        intervalMs: 10,
        clock,
        release: async () => {
          order.push('released');
        },
      }
    ).catch((error: unknown) => error);
    order.push('reported');

    expect(failure).toBeInstanceOf(PollTimeout);
    expect(order).toEqual(['released', 'reported']);
  });

  it('reports the deadline even when the release fails', async () => {
    const clock = fakeClock();

    const failure = await poll(
      () => new Promise<string>(() => {}),
      () => true,
      {
        what: 'the mount to answer',
        timeoutMs: 50,
        intervalMs: 10,
        clock,
        release: () => Promise.reject(new Error('the mount would not release')),
      }
    ).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(PollTimeout);
    expect((failure as PollTimeout).stalled).toBe(true);
  });

  it('frees nothing when every read answered and only the deadline passed', async () => {
    const clock = fakeClock();
    let released = false;

    const failure = await poll(
      () => 'opening',
      () => false,
      {
        what: 'the mount to open',
        timeoutMs: 50,
        intervalMs: 10,
        clock,
        release: async () => {
          released = true;
        },
      }
    ).catch((error: unknown) => error);

    expect((failure as PollTimeout).stalled).toBe(false);
    expect(released).toBe(false);
  });

  it('cancels its alarm, so no timer outlives the wait', async () => {
    const clock = fakeClock();

    await poll(
      () => 'mounted',
      (state) => state === 'mounted',
      {
        what: 'a mounted state',
        timeoutMs: 1000,
        intervalMs: 10,
        clock,
      }
    );

    expect(clock.cancelled()).toBe(1);
  });

  it('handles a probe whose value JSON cannot describe', async () => {
    const clock = fakeClock();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;

    const failure = await poll(
      () => cyclic,
      () => false,
      {
        what: 'an impossible value',
        timeoutMs: 10,
        intervalMs: 10,
        clock,
      }
    ).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(PollTimeout);
    expect((failure as PollTimeout).last).toBe(cyclic);
  });
});

describe('REAL_CLOCK', () => {
  it('fires an alarm it was given, and drops one it was told to cancel', async () => {
    // The alarm is unref'd, so each race carries a ref'd wait of its own to
    // hold the loop open for the outcome under test.
    const fired = await Promise.race([
      REAL_CLOCK.alarm(1).expired.then(() => 'fired'),
      REAL_CLOCK.wait(200).then(() => 'still waiting'),
    ]);
    expect(fired).toBe('fired');

    const cancelled = REAL_CLOCK.alarm(1);
    cancelled.cancel();
    const dropped = await Promise.race([
      cancelled.expired.then(() => 'fired'),
      REAL_CLOCK.wait(50).then(() => 'still waiting'),
    ]);
    expect(dropped).toBe('still waiting');
  });
});
