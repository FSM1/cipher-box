import { describe, expect, it } from 'vitest';
import { ControlProtocolError, ControlRefusal, REFRESH_OVERDUE } from '../control';
import type { PollClock } from '../poll';
import { refreshPastOverdue } from './refresh';

/** A clock the test drives: a refresh costs `costMs`, a wait costs what it asks. */
function fakeClock(): PollClock & { advance(ms: number): void; waits: number[] } {
  let millis = 0;
  const waits: number[] = [];
  return {
    now: () => millis,
    wait: async (ms) => {
      waits.push(ms);
      millis += ms;
    },
    alarm: () => ({ expired: new Promise<void>(() => undefined), cancel: () => undefined }),
    advance: (ms) => {
      millis += ms;
    },
    waits,
  };
}

const overdue = () => new ControlRefusal('refresh', REFRESH_OVERDUE);

/** A refresh that answers each of `answers` in turn, each after `costMs`. */
function refreshes(clock: ReturnType<typeof fakeClock>, costMs: number, answers: (Error | null)[]) {
  let sent = 0;
  const refresh = async (): Promise<void> => {
    const answer = answers[sent++];
    clock.advance(costMs);
    if (answer) throw answer;
  };
  return { refresh, sent: () => sent };
}

function options(clock: PollClock, untilMs: number, lines: string[]) {
  return {
    name: 'linux-writer',
    untilMs,
    intervalMs: 3_000,
    clock,
    log: (line: string) => lines.push(line),
  };
}

describe('a soak refresh', () => {
  it('sends an overdue refresh again until it lands, and logs each overdue answer with its time', async () => {
    const clock = fakeClock();
    const lines: string[] = [];
    const { refresh, sent } = refreshes(clock, 30_000, [overdue(), overdue(), null]);

    await refreshPastOverdue(refresh, options(clock, 300_000, lines));

    expect(sent()).toBe(3);
    expect(clock.waits).toEqual([3_000, 3_000]);
    expect(lines).toEqual([
      '  linux-writer: refresh 1 was overdue after 30000ms (30000ms since the first); it retries\n',
      '  linux-writer: refresh 2 was overdue after 30000ms (63000ms since the first); it retries\n',
    ]);
  });

  it('fails with the overdue refusal once the step budget leaves no room for a retry', async () => {
    const clock = fakeClock();
    const lines: string[] = [];
    const { refresh, sent } = refreshes(clock, 30_000, [overdue(), overdue(), null]);

    const failure = await refreshPastOverdue(refresh, options(clock, 32_000, lines)).catch(
      (error: unknown) => error
    );

    expect(failure).toBeInstanceOf(ControlRefusal);
    expect((failure as ControlRefusal).refusal).toBe(REFRESH_OVERDUE);
    expect(sent()).toBe(1);
    expect(clock.waits).toEqual([]);
    expect(lines).toEqual([
      '  linux-writer: refresh 1 was overdue after 30000ms (30000ms since the first); the step budget is spent\n',
    ]);
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
    ['the overdue text on another verb', new ControlRefusal('status', REFRESH_OVERDUE)],
    [
      'a protocol error',
      new ControlProtocolError('the control endpoint did not answer within 180000ms'),
    ],
  ])('ends the step at once on %s', async (_, answer) => {
    const clock = fakeClock();
    const lines: string[] = [];
    const { refresh, sent } = refreshes(clock, 1_000, [answer, null]);

    await expect(refreshPastOverdue(refresh, options(clock, 300_000, lines))).rejects.toBe(answer);
    expect(sent()).toBe(1);
    expect(clock.waits).toEqual([]);
    expect(lines).toEqual([]);
  });
});
