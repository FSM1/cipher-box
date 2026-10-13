import { DataSource, Migration } from 'typeorm';
import { migrationRunLockKey } from './common/advisory-lock';

const LOCK_POLL_MS = 250;

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Apply the pending migrations under one session advisory lock, so a second
 * runner waits for the first and then finds nothing pending. A session lock,
 * because the run spans one transaction per migration, or none for a migration
 * with `transaction = false`. The waiter polls `pg_try_advisory_lock` and never
 * blocks in a statement: a blocked statement holds a snapshot, and a
 * `CREATE INDEX CONCURRENTLY` in the holder's run waits for every older
 * snapshot, so a blocking wait would hang both runners.
 */
export async function runMigrationsLocked(dataSource: DataSource): Promise<Migration[]> {
  const key = migrationRunLockKey().toString();
  const runner = dataSource.createQueryRunner();
  await runner.connect();
  try {
    for (;;) {
      const [{ acquired }]: { acquired: boolean }[] = await runner.query(
        'SELECT pg_try_advisory_lock($1::bigint) AS acquired',
        [key]
      );
      if (acquired) {
        break;
      }
      await delay(LOCK_POLL_MS);
    }
    try {
      return await dataSource.runMigrations();
    } finally {
      // An unlock failure means a dead connection, whose session lock Postgres
      // has already dropped.
      await runner.query('SELECT pg_advisory_unlock($1::bigint)', [key]).catch(() => undefined);
    }
  } finally {
    await runner.release();
  }
}
