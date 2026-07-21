import { QueryFailedError } from 'typeorm';
import { describe, expect, it } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { isLockNotAvailable, resolveAdvisoryLockTimeoutMs } from './advisory-lock';

/** The safe fail-closed bound applied to an unset or garbage config value. */
const DEFAULT = 3000;

describe('resolveAdvisoryLockTimeoutMs', () => {
  const resolve = (value: string | undefined): number =>
    resolveAdvisoryLockTimeoutMs(fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: value }).service);

  it.each([
    ['unset', undefined, DEFAULT],
    ['empty string', '', DEFAULT],
    ['whitespace', '  ', DEFAULT],
    ['explicit disable', '0', 0],
    ['non-numeric', 'abc', DEFAULT],
    ['negative', '-5', DEFAULT],
    ['valid bound', '5000', 5000],
  ])('%s -> %d', (_label, value, expected) => {
    expect(resolve(value)).toBe(expected);
  });
});

describe('isLockNotAvailable', () => {
  it('is true for a QueryFailedError whose driverError.code is 55P03', () => {
    const err = new QueryFailedError('SELECT 1', [], { code: '55P03' } as never);
    expect(isLockNotAvailable(err)).toBe(true);
  });

  it('is true when the 55P03 code sits directly on the QueryFailedError', () => {
    const err = new QueryFailedError('SELECT 1', [], {} as never);
    (err as unknown as { code: string }).code = '55P03';
    expect(isLockNotAvailable(err)).toBe(true);
  });

  it('is false for a QueryFailedError with a different code', () => {
    const err = new QueryFailedError('SELECT 1', [], { code: '23505' } as never);
    expect(isLockNotAvailable(err)).toBe(false);
  });

  it.each([
    ['a plain Error', new Error('nope')],
    ['a bare code-bearing object', { code: '55P03' } as unknown],
    ['undefined', undefined],
  ])('is false for %s (not a QueryFailedError)', (_label, value) => {
    expect(isLockNotAvailable(value)).toBe(false);
  });
});
