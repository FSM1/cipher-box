import { describe, expect, it } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { DEFAULT_DB_POOL_SIZE, resolveDbPoolSize } from './db-pool';

const resolve = (value: string | undefined): number =>
  resolveDbPoolSize(fakeConfig({ DB_POOL_SIZE: value }).service);

describe('resolveDbPoolSize', () => {
  it('honors a valid explicit ceiling', () => {
    expect(resolve('20')).toBe(20);
  });

  it('fails closed to the default for unset, empty, or garbage', () => {
    expect(resolve(undefined)).toBe(DEFAULT_DB_POOL_SIZE);
    expect(resolve('   ')).toBe(DEFAULT_DB_POOL_SIZE);
    expect(resolve('not-a-number')).toBe(DEFAULT_DB_POOL_SIZE);
    expect(resolve('4.5')).toBe(DEFAULT_DB_POOL_SIZE);
  });

  it('rejects a non-positive ceiling (a zero-size pool would deadlock)', () => {
    expect(resolve('0')).toBe(DEFAULT_DB_POOL_SIZE);
    expect(resolve('-3')).toBe(DEFAULT_DB_POOL_SIZE);
  });
});
