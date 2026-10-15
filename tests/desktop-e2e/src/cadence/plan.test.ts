import { describe, expect, it } from 'vitest';
import { EVERY_ENV, SPAN_ENV, cadenceOf, line, nextStart, verdict, type MountResult } from './plan';

const cadence = { spanMs: 20_000, everyMs: 5_000 };

function result(offsetMs: number, outcome: MountResult['outcome'] = 'live'): MountResult {
  return { offsetMs, outcome, tookMs: 300, detail: 'mounted' };
}

describe('the mount-cadence plan', () => {
  it('reads its cadence from the environment, with defaults', () => {
    expect(cadenceOf({})).toEqual({ spanMs: 160_000, everyMs: 5_000 });
    expect(cadenceOf({ [SPAN_ENV]: '9000', [EVERY_ENV]: '3000' })).toEqual({
      spanMs: 9_000,
      everyMs: 3_000,
    });
    expect(() => cadenceOf({ [EVERY_ENV]: '0' })).toThrow(EVERY_ENV);
    expect(() => cadenceOf({ [SPAN_ENV]: 'soon' })).toThrow(SPAN_ENV);
  });

  it('starts on the next free slot and stops after the span', () => {
    expect(nextStart(cadence, 0)).toBe(0);
    expect(nextStart(cadence, 1_200)).toBe(5_000);
    expect(nextStart(cadence, 5_000)).toBe(5_000);
    // A mount that hung for 30 s gives up the slots it overran.
    expect(nextStart({ spanMs: 160_000, everyMs: 5_000 }, 125_000 + 31_000)).toBe(160_000);
    expect(nextStart(cadence, 20_001)).toBeNull();
  });

  it('reports each failed mount', () => {
    const results = [0, 5_000, 10_000, 15_000].map((at) => result(at));
    results.push(result(20_000, 'failed'));
    expect(verdict(cadence, results)).toEqual([results[4]]);
    expect(verdict(cadence, results.slice(0, 4).concat(result(20_000)))).toEqual([]);
  });

  it('reports a late failure that ended the run before the span', () => {
    const results = [0, 5_000, 10_000].map((at) => result(at));
    results.push(result(13_000, 'failed'));
    expect(verdict(cadence, results)).toEqual([results[3]]);
    const long = { spanMs: 160_000, everyMs: 5_000 };
    expect(verdict(long, [result(0), result(130_000, 'failed')])).toEqual([
      result(130_000, 'failed'),
    ]);
  });

  it('refuses a run that ended before the span', () => {
    expect(() => verdict(cadence, [result(0), result(5_000)])).toThrow('short of');
  });

  it('logs the offset, outcome and time of each mount', () => {
    expect(line(result(125_000, 'failed'))).toBe('+125.0s failed after 300ms: mounted');
  });
});
