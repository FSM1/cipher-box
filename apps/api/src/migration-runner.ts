import { Logger } from '@nestjs/common';
import { DataSource, Migration } from 'typeorm';
import { MIGRATION_RUN_LOCK_NAME as LOCK_NAME, migrationRunLockKey } from './common/advisory-lock';

const LOCK_POLL_MS = 250;

/** A deploy whose runner waits this long behind another one fails with a named error. */
export const MIGRATION_LOCK_WAIT_DEADLINE_MS = 10 * 60 * 1000;

const logger = new Logger('MigrationRunner');

/** No lock in the deadline: another runner holds it, or a session that never let go. */
export class MigrationLockTimeoutError extends Error {
  constructor(waitedMs: number) {
    super(`the ${LOCK_NAME} advisory lock stayed held for ${waitedMs} ms`);
    this.name = 'MigrationLockTimeoutError';
  }
}

/** The run finished, but its session could not release the lock and was closed. */
export class MigrationLockReleaseError extends Error {
  constructor(cause: unknown) {
    super(`the ${LOCK_NAME} advisory lock did not release; its session was closed`, { cause });
    this.name = 'MigrationLockReleaseError';
  }
}

export interface MigrationLockOptions {
  /** Wall-clock milliseconds; injected so a test can pass the deadline. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

const sleepMs = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Apply the pending migrations under one session advisory lock, so a second
 * runner waits for the first and then finds nothing pending. A session lock,
 * because the run spans one transaction per migration, or none for a migration
 * with `transaction = false`. The waiter polls `pg_try_advisory_lock` and never
 * blocks in a statement: a blocked statement holds a snapshot, and a
 * `CREATE INDEX CONCURRENTLY` in the holder's run waits for every older
 * snapshot, so a blocking wait would hang both runners.
 */
export async function runMigrationsLocked(
  dataSource: DataSource,
  options: MigrationLockOptions = {}
): Promise<Migration[]> {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? sleepMs;
  const key = migrationRunLockKey().toString();
  const runner = dataSource.createQueryRunner();
  const session = (await runner.connect()) as { end?: () => Promise<void> };
  try {
    const started = now();
    for (let attempt = 0; ; attempt += 1) {
      const [{ acquired }]: { acquired: boolean }[] = await runner.query(
        'SELECT pg_try_advisory_lock($1::bigint) AS acquired',
        [key]
      );
      if (acquired) {
        break;
      }
      if (attempt === 0) {
        logger.log(`waiting for the ${LOCK_NAME} advisory lock that another runner holds`);
      }
      const waited = now() - started;
      if (waited >= MIGRATION_LOCK_WAIT_DEADLINE_MS) {
        throw new MigrationLockTimeoutError(waited);
      }
      await sleep(LOCK_POLL_MS);
    }

    let applied: Migration[];
    try {
      applied = await dataSource.runMigrations();
    } catch (error) {
      await unlockOrClose(runner, session, key).catch((cleanup: unknown) => {
        logger.error(`${String(cleanup)}; the run failed first`);
      });
      throw error;
    }
    await unlockOrClose(runner, session, key);
    return applied;
  } finally {
    await runner.release();
  }
}

/**
 * A session whose unlock failed may still hold the lock, so it is closed rather
 * than returned to the pool: Postgres drops a session lock when its backend exits,
 * and the pool discards a closed client on release.
 */
async function unlockOrClose(
  runner: ReturnType<DataSource['createQueryRunner']>,
  session: { end?: () => Promise<void> },
  key: string
): Promise<void> {
  try {
    await runner.query('SELECT pg_advisory_unlock($1::bigint)', [key]);
  } catch (unlockError) {
    await session.end?.().catch(() => undefined);
    throw new MigrationLockReleaseError(unlockError);
  }
}
