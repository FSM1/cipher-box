import { describe, expect, it } from 'vitest';
import { group, parseSamples, percentile, renderWaits } from './waits';

const LINES = [
  '{"what":"host-b to list a.txt at the vault root","elapsedMs":2000,"attempts":3}',
  '{"what":"host-b to list a.txt at the vault root","elapsedMs":4000,"attempts":5}',
  '{"what":"the mount to project a.txt","elapsedMs":1000,"attempts":2}',
].join('\n');

describe('parseSamples', () => {
  it('reads every sample and ignores the trailing newline', () => {
    expect(parseSamples(`${LINES}\n`)).toHaveLength(3);
  });

  it('refuses a line that is not a wait sample', () => {
    expect(() => parseSamples('{"what":"a wait"}')).toThrow(/sample 1 is not a wait sample/);
  });

  it('refuses a line that is not an object', () => {
    expect(() => parseSamples('42')).toThrow(/sample 1 is not an object/);
  });

  it('refuses an elapsed time no wait can produce', () => {
    // 1e400 parses to Infinity, which `typeof` calls a number.
    const overflowed = '{"what":"a wait","elapsedMs":1e400,"attempts":1}';
    expect(() => parseSamples(overflowed)).toThrow(/sample 1 is not a wait sample/);

    const negative = '{"what":"a wait","elapsedMs":-1,"attempts":1}';
    expect(() => parseSamples(negative)).toThrow(/sample 1 is not a wait sample/);
  });

  it('refuses a read count that is fractional or negative', () => {
    const fractional = '{"what":"a wait","elapsedMs":10,"attempts":1.5}';
    expect(() => parseSamples(fractional)).toThrow(/sample 1 is not a wait sample/);

    const negative = '{"what":"a wait","elapsedMs":10,"attempts":-2}';
    expect(() => parseSamples(negative)).toThrow(/sample 1 is not a wait sample/);
  });

  it('takes a wait that settled on its first read with no time on the clock', () => {
    const instant = '{"what":"a wait","elapsedMs":0,"attempts":1}';
    expect(parseSamples(instant)).toEqual([{ what: 'a wait', elapsedMs: 0, attempts: 1 }]);
  });

  it('takes a fractional elapsed time, which a clock can produce', () => {
    const fractional = '{"what":"a wait","elapsedMs":0.5,"attempts":1}';
    expect(parseSamples(fractional)[0].elapsedMs).toBe(0.5);
  });
});

describe('group', () => {
  const groups = group(parseSamples(LINES));

  it('writes one row per wait, worst first', () => {
    expect(groups.map((row) => row.what)).toEqual([
      'host-b to list a.txt at the vault root',
      'the mount to project a.txt',
    ]);
  });

  it('carries the percentiles and the worst read count of each wait', () => {
    expect(groups[0]).toEqual({
      what: 'host-b to list a.txt at the vault root',
      count: 2,
      p50Ms: 2000,
      p95Ms: 4000,
      maxMs: 4000,
      maxAttempts: 5,
    });
  });
});

describe('percentile', () => {
  it('takes the nearest rank, as the load harness does', () => {
    expect(percentile([1, 2, 3, 4], 50)).toBe(2);
    expect(percentile([1, 2, 3, 4], 95)).toBe(4);
    expect(percentile([7], 99)).toBe(7);
  });

  it('refuses an empty series rather than answering zero', () => {
    expect(() => percentile([], 50)).toThrow(/no samples/);
  });
});

describe('renderWaits', () => {
  it('writes a header and one row per wait', () => {
    expect(renderWaits(group(parseSamples(LINES))).split('\n')).toHaveLength(4);
  });
});
