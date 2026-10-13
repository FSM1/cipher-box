import { describe, expect, it } from 'vitest';
import { ControlProtocolError, ControlRefusal } from '../control';
import type { PollClock } from '../poll';
import { refreshPastOverdue } from './refresh';

// The literal, not `REFRESH_OVERDUE`: the engine states it in
// `ForcedPass::landed`, so a copy on each side would let the two drift unseen.
const OVERDUE_TEXT = 'refresh failed: the pass did not land within the refresh deadline';

/** The production pace: one 30 s tick between retries, a 30 s engine deadline. */
const WAIT_MS = 30_000;
const REFRESH_DEADLINE_MS = 30_000;

/**
 * A clock the test drives. A wait ends on a later macrotask, and a wait can
 * end late by `lateByMs`, so a helper that does not await it, or that trusts
 * its length, fails the test.
 */
function fakeClock(lateByMs = 0) {
  let millis = 0;
  let pending = 0;
  const waits: number[] = [];
  const clock: PollClock = {
    now: () => millis,
    wait: (ms) => {
      waits.push(ms);
      pending += 1;
      return new Promise<void>((resolve) =>
        setTimeout(() => {
          millis += ms + lateByMs;
          pending -= 1;
          resolve();
        }, 0)
      );
    },
    alarm: () => ({ expired: new Promise<void>(() => undefined), cancel: () => undefined }),
  };
  return {
    clock,
    waits,
    advance: (ms: number) => {
      millis += ms;
    },
    waiting: () => pending > 0,
  };
}

type Answer = { costMs: number; error?: Error };

const overdue = (costMs: number): Answer => ({
  costMs,
  error: new ControlRefusal('refresh', OVERDUE_TEXT),
});
const landed = (costMs: number): Answer => ({ costMs });

/** A refresh that gives each answer in turn, and fails if a wait is still open. */
function refreshes(fake: ReturnType<typeof fakeClock>, answers: Answer[]) {
  let sent = 0;
  const refresh = async (): Promise<void> => {
    if (fake.waiting()) throw new Error('a refresh was sent before its wait ended');
    const answer = answers[sent++];
    fake.advance(answer.costMs);
    if (answer.error) throw answer.error;
  };
  return { refresh, sent: () => sent };
}

function run(fake: ReturnType<typeof fakeClock>, refresh: () => Promise<void>, untilMs: number) {
  const lines: string[] = [];
  const done = refreshPastOverdue(refresh, {
    name: 'linux-writer',
    untilMs,
    waitMs: WAIT_MS,
    refreshDeadlineMs: REFRESH_DEADLINE_MS,
    clock: fake.clock,
    log: (line) => lines.push(line),
  });
  return { done, lines };
}

async function overdueFailure(done: Promise<void>): Promise<ControlRefusal> {
  const failure = await done.then(
    () => undefined,
    (error: unknown) => error
  );
  expect(failure).toBeInstanceOf(ControlRefusal);
  expect((failure as ControlRefusal).refusal).toBe(OVERDUE_TEXT);
  return failure as ControlRefusal;
}

describe('a soak refresh', () => {
  it('waits one tick after each overdue answer that comes at once, and logs the first and the result', async () => {
    const fake = fakeClock();
    const { refresh, sent } = refreshes(fake, [overdue(0), overdue(0), overdue(0), landed(2_000)]);

    const { done, lines } = run(fake, refresh, 450_000);
    await done;

    expect(sent()).toBe(4);
    expect(fake.waits).toEqual([WAIT_MS, WAIT_MS, WAIT_MS]);
    expect(lines).toEqual([
      '  linux-writer: refresh 1 was overdue after 0ms; it retries every 30000ms\n',
      '  linux-writer: refresh landed on attempt 4, 92000ms after the first\n',
    ]);
  });

  it('starts no retry when the budget leaves no wait and refresh deadline', async () => {
    const fake = fakeClock();
    const { refresh, sent } = refreshes(fake, [overdue(30_000), landed(0)]);

    const { done, lines } = run(fake, refresh, 90_000);
    await overdueFailure(done);

    expect(sent()).toBe(1);
    expect(fake.waits).toEqual([]);
    expect(lines).toEqual([
      '  linux-writer: refresh 1 was overdue after 30000ms; it retries every 30000ms\n',
      '  linux-writer: refresh was overdue on attempt 1, 30000ms after the first; the step budget is spent\n',
    ]);
  });

  it('starts no retry after a wait that ended late', async () => {
    const fake = fakeClock(15_000);
    const { refresh, sent } = refreshes(fake, [overdue(30_000), landed(0)]);

    const { done, lines } = run(fake, refresh, 100_000);
    await overdueFailure(done);

    expect(sent()).toBe(1);
    expect(fake.waits).toEqual([WAIT_MS]);
    expect(lines.at(-1)).toBe(
      '  linux-writer: refresh was overdue on attempt 1, 75000ms after the first; the step budget is spent\n'
    );
  });

  it('fails with the overdue refusal when a retry lands past the budget', async () => {
    const fake = fakeClock();
    const { refresh, sent } = refreshes(fake, [overdue(30_000), landed(45_000)]);

    const { done, lines } = run(fake, refresh, 100_000);
    await overdueFailure(done);

    expect(sent()).toBe(2);
    expect(lines.at(-1)).toBe(
      '  linux-writer: refresh landed late on attempt 2, 105000ms after the first; the step budget is spent\n'
    );
  });

  it('fails with the overdue refusal when a retry still runs at the end of the budget', async () => {
    const fake = fakeClock();
    const { refresh, sent } = refreshes(fake, [overdue(30_000), overdue(45_000), landed(0)]);

    const { done, lines } = run(fake, refresh, 100_000);
    await overdueFailure(done);

    expect(sent()).toBe(2);
    expect(fake.waits).toEqual([WAIT_MS]);
    expect(lines.at(-1)).toBe(
      '  linux-writer: refresh was overdue on attempt 2, 105000ms after the first; the step budget is spent\n'
    );
  });

  it.each([
    [
      'an unreachable verdict',
      new ControlRefusal(
        'refresh',
        'refresh failed: no endpoint served a record this pass could adopt'
      ),
    ],
    [
      'a trust violation',
      new ControlRefusal(
        'refresh',
        'trust violation: the record plane served a record the adoption gate rejected'
      ),
    ],
    ['the overdue text on another verb', new ControlRefusal('status', OVERDUE_TEXT)],
    [
      'a protocol error',
      new ControlProtocolError('the control endpoint did not answer within 180000ms'),
    ],
  ])('ends the step at once on %s', async (_, error) => {
    const fake = fakeClock();
    const { refresh, sent } = refreshes(fake, [{ costMs: 1_000, error }, landed(0)]);

    const { done, lines } = run(fake, refresh, 450_000);
    await expect(done).rejects.toBe(error);
    expect(sent()).toBe(1);
    expect(fake.waits).toEqual([]);
    expect(lines).toEqual([]);
  });
});
