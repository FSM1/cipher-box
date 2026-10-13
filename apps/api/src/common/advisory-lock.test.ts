import { Logger, ServiceUnavailableException } from '@nestjs/common';
import { DataSource, QueryFailedError } from 'typeorm';
import { describe, expect, it, vi } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import {
  isLockNotAvailable,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  withSessionAdvisoryLock,
} from './advisory-lock';

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

  it('is true for a full shared lock table (53200 with the lock manager hint)', () => {
    const err = new QueryFailedError('SELECT 1', [], {
      code: '53200',
      hint: 'You might need to increase max_locks_per_transaction.',
    } as never);
    expect(isLockNotAvailable(err)).toBe(true);
  });

  it.each([
    ['another hint', 'You might need to increase max_pred_locks_per_transaction.'],
    ['no hint', undefined],
  ])('is false for a 53200 with %s', (_label, hint) => {
    const err = new QueryFailedError('SELECT 1', [], { code: '53200', hint } as never);
    expect(isLockNotAvailable(err)).toBe(false);
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

describe('runLockGuardedTransaction', () => {
  const failingWith = (driverError: object) =>
    ({
      transaction: () => Promise.reject(new QueryFailedError('SELECT 1', [], driverError as never)),
    }) as unknown as DataSource;

  it('answers a full lock table with a 503 and one warning', async () => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    try {
      await expect(
        runLockGuardedTransaction(
          failingWith({
            code: '53200',
            hint: 'You might need to increase max_locks_per_transaction.',
          }),
          async () => undefined
        )
      ).rejects.toBeInstanceOf(ServiceUnavailableException);
      expect(warn).toHaveBeenCalledOnce();
    } finally {
      warn.mockRestore();
    }
  });

  it('passes any other 53200 through unchanged, with no warning', async () => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    try {
      await expect(
        runLockGuardedTransaction(failingWith({ code: '53200' }), async () => undefined)
      ).rejects.toBeInstanceOf(QueryFailedError);
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});

describe('withSessionAdvisoryLock', () => {
  /** One pooled session whose unlock fails as told. */
  function fakePool(unlockFails: boolean) {
    const end = vi.fn().mockResolvedValue(undefined);
    const release = vi.fn().mockResolvedValue(undefined);
    const dataSource = {
      createQueryRunner: () => ({
        connect: async () => ({ end }),
        query: (sql: string) =>
          unlockFails && sql.includes('pg_advisory_unlock')
            ? Promise.reject(new Error('canceling statement due to user request'))
            : Promise.resolve([]),
        release,
      }),
    } as unknown as DataSource;
    return { dataSource, end, release };
  }

  it('closes the session when the unlock fails, and still returns the work result', async () => {
    const error = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    try {
      const pool = fakePool(true);
      await expect(
        withSessionAdvisoryLock(pool.dataSource, 1n, 0, async () => 'done')
      ).resolves.toBe('done');
      expect(pool.end).toHaveBeenCalledOnce();
      expect(pool.release).toHaveBeenCalledOnce();
      expect(error).toHaveBeenCalledOnce();
    } finally {
      error.mockRestore();
    }
  });

  it('keeps the session open after a clean unlock', async () => {
    const pool = fakePool(false);
    await withSessionAdvisoryLock(pool.dataSource, 1n, 0, async () => undefined);
    expect(pool.end).not.toHaveBeenCalled();
    expect(pool.release).toHaveBeenCalledOnce();
  });
});
