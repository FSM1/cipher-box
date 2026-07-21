import { describe, expect, it } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { resolveAdvisoryLockTimeoutMs } from './advisory-lock';

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
