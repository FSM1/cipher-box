import { Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  MIGRATION_LOCK_WAIT_DEADLINE_MS,
  MigrationLockReleaseError,
  MigrationLockTimeoutError,
  runMigrationsLocked,
} from './migration-runner';

interface FakeSession {
  dataSource: DataSource;
  runMigrations: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
  release: ReturnType<typeof vi.fn>;
  queries: string[];
}

/** A DataSource whose one session answers the try-lock and the unlock as told. */
function fakeSession(lock: { acquired: boolean }, unlock: () => Promise<unknown>): FakeSession {
  const queries: string[] = [];
  const end = vi.fn().mockResolvedValue(undefined);
  const release = vi.fn().mockResolvedValue(undefined);
  const runMigrations = vi.fn().mockResolvedValue([]);
  const runner = {
    connect: () => Promise.resolve({ end }),
    query: (sql: string) => {
      queries.push(sql);
      return sql.includes('pg_try_advisory_lock') ? Promise.resolve([lock]) : unlock();
    },
    release,
  };
  const dataSource = { createQueryRunner: () => runner, runMigrations } as unknown as DataSource;
  return { dataSource, runMigrations, end, release, queries };
}

describe('runMigrationsLocked', () => {
  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it('gives up with a named error at the deadline, logs the wait once, and runs nothing', async () => {
    const fake = fakeSession({ acquired: false }, () => Promise.resolve([]));
    let clock = 0;
    const run = runMigrationsLocked(fake.dataSource, {
      now: () => clock,
      sleep: async (ms) => {
        clock += ms;
      },
    });

    await expect(run).rejects.toBeInstanceOf(MigrationLockTimeoutError);
    expect(clock).toBeGreaterThanOrEqual(MIGRATION_LOCK_WAIT_DEADLINE_MS);
    expect(fake.runMigrations).not.toHaveBeenCalled();
    expect(Logger.prototype.log).toHaveBeenCalledOnce();
    expect(fake.release).toHaveBeenCalledOnce();
  });

  it('closes the session when the unlock fails, and reports it', async () => {
    const fake = fakeSession({ acquired: true }, () => Promise.reject(new Error('canceled')));

    const run = runMigrationsLocked(fake.dataSource);

    await expect(run).rejects.toBeInstanceOf(MigrationLockReleaseError);
    expect(fake.runMigrations).toHaveBeenCalledOnce();
    expect(fake.end).toHaveBeenCalledOnce();
    expect(fake.release).toHaveBeenCalledOnce();
  });

  it('closes the session when the unlock fails after a failed run, and keeps the run error', async () => {
    const fake = fakeSession({ acquired: true }, () => Promise.reject(new Error('canceled')));
    const failure = new Error('migration failed');
    fake.runMigrations.mockRejectedValue(failure);

    await expect(runMigrationsLocked(fake.dataSource)).rejects.toBe(failure);
    expect(fake.end).toHaveBeenCalledOnce();
    expect(fake.release).toHaveBeenCalledOnce();
  });

  it('unlocks and keeps the session after a clean run', async () => {
    const fake = fakeSession({ acquired: true }, () => Promise.resolve([{}]));

    await expect(runMigrationsLocked(fake.dataSource)).resolves.toEqual([]);
    expect(fake.queries.some((sql) => sql.includes('pg_advisory_unlock'))).toBe(true);
    expect(fake.end).not.toHaveBeenCalled();
    expect(fake.release).toHaveBeenCalledOnce();
  });
});
