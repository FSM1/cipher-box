import { describe, expect, it } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { resolvePinConcurrency } from './content.service';

const resolve = (values: Record<string, string | undefined>) =>
  resolvePinConcurrency(fakeConfig(values).service);

describe('resolvePinConcurrency', () => {
  it('defaults to 4 under the default pool of 10', () => {
    expect(resolve({})).toEqual({ ceiling: 4 });
  });

  it('honors a configured ceiling that respects the 2x pool bound', () => {
    expect(resolve({ CONTENT_PIN_CONCURRENCY: '3', DB_POOL_SIZE: '10' })).toEqual({ ceiling: 3 });
  });

  it('clamps a ceiling that would violate 2 x ceiling <= poolSize (config drift)', () => {
    // 2 x 20 > 10: an admitted upload transiently holds 2 connections, so the
    // safe max is floor(pool / 2) = 5. The unsafe value is reported for logging.
    expect(resolve({ CONTENT_PIN_CONCURRENCY: '20', DB_POOL_SIZE: '10' })).toEqual({
      ceiling: 5,
      clampedFrom: 20,
    });
  });

  it('scales the safe max with the pool size', () => {
    // A larger pool raises the safe max to floor(40 / 2) = 20; 25 fits, 30 clamps.
    expect(resolve({ CONTENT_PIN_CONCURRENCY: '18', DB_POOL_SIZE: '40' })).toEqual({ ceiling: 18 });
    expect(resolve({ CONTENT_PIN_CONCURRENCY: '30', DB_POOL_SIZE: '40' })).toEqual({
      ceiling: 20,
      clampedFrom: 30,
    });
  });

  it('refuses the pin path (ceiling 0) for a pool too small to host one upload', () => {
    // An admitted upload needs 2 pooled connections (session lock + commit tx),
    // so a pool of 1 would self-deadlock. floor(1 / 2) = 0 disables the path and
    // upload() fails closed with 503 rather than admitting an unfinishable request.
    expect(resolve({ CONTENT_PIN_CONCURRENCY: '4', DB_POOL_SIZE: '1' })).toEqual({
      ceiling: 0,
      clampedFrom: 4,
    });
  });

  it('admits exactly one upload at the minimum viable pool of 2', () => {
    // floor(2 / 2) = 1: one upload holds both connections, none to spare, but no
    // deadlock — the smallest pool the pin path can serve.
    expect(resolve({ CONTENT_PIN_CONCURRENCY: '4', DB_POOL_SIZE: '2' })).toEqual({
      ceiling: 1,
      clampedFrom: 4,
    });
  });

  it('fails closed to the default before clamping for a garbage ceiling', () => {
    expect(resolve({ CONTENT_PIN_CONCURRENCY: 'nonsense', DB_POOL_SIZE: '10' })).toEqual({
      ceiling: 4,
    });
  });
});
