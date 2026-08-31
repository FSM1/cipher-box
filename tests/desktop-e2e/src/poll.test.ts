import { describe, expect, it } from 'vitest';
import { poll, PollTimeout, type PollClock } from './poll';

/** A clock the test drives, so no unit test spends real time. */
function fakeClock(): PollClock & { elapsed(): number } {
  let millis = 0;
  return {
    now: () => millis,
    wait: async (ms) => {
      millis += ms;
    },
    elapsed: () => millis,
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
