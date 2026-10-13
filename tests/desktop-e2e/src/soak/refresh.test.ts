import { describe, expect, it, vi } from 'vitest';
import { ControlProtocolError, ControlRefusal } from '../control';
import { PollTimeout, poll, type PollClock } from '../poll';
import { refreshPastOverdue } from './refresh';

// The literal, not `REFRESH_OVERDUE`: the engine states it in
// `ForcedPass::landed`, so a copy on each side would let the two drift unseen.
const OVERDUE_TEXT = 'refresh failed: the pass did not land within the refresh deadline';

/** One tick between retries, and the engine refresh deadline, as the soak runs them. */
const WAIT_MS = 30_000;
const REFRESH_DEADLINE_MS = 30_000;

/**
 * A clock the test drives. Each wait, alarm and refresh answer is an event at
 * a fake time, and one event fires per macrotask in time order, so every
 * promise settles between two events. A wait can end late by `lateByMs`.
 */
function fakeClock(lateByMs = 0) {
  let millis = 0;
  let order = 0;
  let pumping = false;
  let openWaits = 0;
  const events: { at: number; order: number; fire: () => void }[] = [];
  const waits: number[] = [];

  const pump = () => {
    if (pumping) return;
    pumping = true;
    setTimeout(() => {
      pumping = false;
      events.sort((one, other) => one.at - other.at || one.order - other.order);
      const next = events.shift();
      if (!next) return;
      millis = Math.max(millis, next.at);
      next.fire();
      if (events.length > 0) pump();
    }, 0);
  };
  const at = (due: number, fire: () => void) => {
    const event = { at: due, order: order++, fire };
    events.push(event);
    pump();
    return event;
  };

  const clock: PollClock = {
    now: () => millis,
    wait: (ms) => {
      waits.push(ms);
      openWaits += 1;
      return new Promise<void>((resolve) =>
        at(millis + ms + lateByMs, () => {
          openWaits -= 1;
          resolve();
        })
      );
    },
    alarm: (ms) => {
      let fire: () => void = () => undefined;
      const expired = new Promise<void>((resolve) => {
        fire = resolve;
      });
      const event = at(millis + ms, () => fire());
      return {
        expired,
        cancel: () => {
          const index = events.indexOf(event);
          if (index >= 0) events.splice(index, 1);
        },
      };
    },
  };
  return {
    clock,
    waits,
    now: () => millis,
    /** An answer `costMs` from now. */
    answerIn: (costMs: number, settle: () => void) => at(millis + costMs, settle),
    waiting: () => openWaits > 0,
    /** The events not yet fired: a wait, an alarm or an answer. */
    pending: () => events.length,
  };
}

type FakeClock = ReturnType<typeof fakeClock>;
type Answer = { costMs: number; error?: Error } | 'never';

const overdue = (costMs: number): Answer => ({
  costMs,
  error: new ControlRefusal('refresh', OVERDUE_TEXT),
});
const landed = (costMs: number): Answer => ({ costMs });

/** A refresh that gives each answer in turn, and fails if a wait is still open. */
function refreshes(fake: FakeClock, answers: Answer[]) {
  let sent = 0;
  const refresh = (): Promise<void> => {
    if (fake.waiting())
      return Promise.reject(new Error('a refresh was sent before its wait ended'));
    const answer = answers[sent++];
    if (answer === 'never') return new Promise<void>(() => undefined);
    return new Promise<void>((resolve, reject) =>
      fake.answerIn(answer.costMs, () => (answer.error ? reject(answer.error) : resolve()))
    );
  };
  return { refresh, sent: () => sent };
}

function run(fake: FakeClock, refresh: () => Promise<void>, untilMs: number) {
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

async function failure(done: Promise<unknown>): Promise<Error> {
  const error = await done.then(
    () => undefined,
    (thrown: unknown) => thrown
  );
  expect(error).toBeInstanceOf(Error);
  return error as Error;
}

async function overdueFailure(done: Promise<void>): Promise<void> {
  const error = await failure(done);
  expect(error).toBeInstanceOf(ControlRefusal);
  expect((error as ControlRefusal).refusal).toBe(OVERDUE_TEXT);
}

describe('a soak refresh', () => {
  it('waits one tick after each overdue answer that comes at once, and logs the first and the result', async () => {
    const fake = fakeClock();
    const { refresh, sent } = refreshes(fake, [overdue(0), overdue(0), overdue(0), landed(2_000)]);

    const { done, lines } = run(fake, refresh, 450_000);
    await done;

    expect(sent()).toBe(4);
    expect(fake.waits).toEqual([WAIT_MS, WAIT_MS, WAIT_MS]);
    // Each answer that won its race took its alarm away with it.
    expect(fake.pending()).toBe(0);
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
    expect(lines.at(-1)).toBe(
      '  linux-writer: refresh was overdue on attempt 1, 30000ms after the first; the step budget is spent\n'
    );
  });

  it('starts no retry after a late wait that leaves exactly one refresh deadline', async () => {
    const fake = fakeClock(1_000);
    const { refresh, sent } = refreshes(fake, [overdue(30_000), landed(0)]);

    // Overdue at 30 s, 61 s left; the wait ends at 61 s, so 30 s are left.
    const { done, lines } = run(fake, refresh, 91_000);
    await overdueFailure(done);

    expect(sent()).toBe(1);
    expect(fake.waits).toEqual([WAIT_MS]);
    expect(lines.at(-1)).toBe(
      '  linux-writer: refresh was overdue on attempt 1, 61000ms after the first; the step budget is spent\n'
    );
  });

  it('retries after a late wait that leaves one millisecond more than a refresh deadline', async () => {
    const fake = fakeClock(1_000);
    const { refresh, sent } = refreshes(fake, [overdue(30_000), landed(0)]);

    const { done } = run(fake, refresh, 91_001);
    await done;

    expect(sent()).toBe(2);
  });

  it.each([
    ['lands', landed(59_000)],
    ['answers overdue', overdue(59_000)],
  ])(
    'gives the overdue refusal at the margin when a queued retry %s after two refresh deadlines',
    async (_, retry) => {
      const fake = fakeClock();
      const { refresh, sent } = refreshes(fake, [overdue(30_000), retry]);

      // The retry starts at 60 s with 40 s left; it would answer at 119 s.
      const { done, lines } = run(fake, refresh, 100_000);
      await overdueFailure(done);

      expect(sent()).toBe(2);
      expect(fake.now()).toBe(99_000);
      expect(lines.at(-1)).toBe(
        '  linux-writer: refresh got no answer on attempt 2, 99000ms after the first; the step budget is spent\n'
      );
    }
  );

  it('fails a first refresh that never answers one second before the budget ends', async () => {
    const fake = fakeClock();
    const { refresh } = refreshes(fake, ['never']);

    const { done } = run(fake, refresh, 100_000);
    const error = await failure(done);

    expect(error.message).toBe('linux-writer: the refresh got no answer within the step budget');
    expect(fake.now()).toBe(99_000);
  });

  it.each([
    ['fails at the margin when its answer comes after it', 5_000, 2_000, false],
    ['lands when its answer comes before the margin', 500, 500, true],
  ])(
    'gives a first refresh sent with three seconds left: it %s',
    async (_, costMs, endsAtMs, lands) => {
      const fake = fakeClock();
      const { refresh } = refreshes(fake, [landed(costMs)]);

      const { done } = run(fake, refresh, 3_000);
      if (lands) await done;
      else {
        const error = await failure(done);
        expect(error.message).toBe(
          'linux-writer: the refresh got no answer within the step budget'
        );
      }
      expect(fake.now()).toBe(endsAtMs);
    }
  );

  it('fails a poll step with the overdue refusal, not with its poll timeout', async () => {
    const fake = fakeClock();
    const { refresh } = refreshes(fake, [overdue(0), 'never']);
    const release = vi.fn(async () => undefined);
    let reads = 0;

    const waited = poll(
      async () => {
        if (reads++ > 0) await run(fake, refresh, 300_000).done;
        return 'ENOENT';
      },
      (seen) => seen !== 'ENOENT',
      {
        what: 'the grantee ledger to open',
        timeoutMs: 300_000,
        intervalMs: WAIT_MS,
        clock: fake.clock,
        release,
      }
    );
    const error = await failure(waited);

    expect(error).not.toBeInstanceOf(PollTimeout);
    expect((error as ControlRefusal).refusal).toBe(OVERDUE_TEXT);
    expect(fake.now()).toBe(299_000);
    expect(release).not.toHaveBeenCalled();
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
