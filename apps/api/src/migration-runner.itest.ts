import { DataSource } from 'typeorm';
import { afterEach, describe, expect, it } from 'vitest';
import { runMigrationsLocked } from './migration-runner';
import { createIntegrationDatabase, IntegrationDatabase } from './testing/integration-db';

describe('runMigrationsLocked (real Postgres)', () => {
  let db: IntegrationDatabase | undefined;
  let second: DataSource | undefined;

  afterEach(async () => {
    if (second?.isInitialized) {
      await second.destroy();
    }
    await db?.teardown();
  });

  it('applies each migration once when two runners start together on an empty database', async () => {
    db = await createIntegrationDatabase({ migrate: false });
    second = new DataSource(db.dataSource.options);
    await second.initialize();
    const expected = db.dataSource.migrations.map((migration) => migration.name).sort();

    const [first, other] = await Promise.all([
      runMigrationsLocked(db.dataSource),
      runMigrationsLocked(second),
    ]);

    // One runner applies the whole set; the other waits and finds nothing pending.
    expect([first.length, other.length].sort((a, b) => a - b)).toEqual([0, expected.length]);
    const recorded: { name: string }[] = await db.dataSource.query('SELECT name FROM migrations');
    expect(recorded.map((row) => row.name).sort()).toEqual(expected);
    expect(await db.dataSource.showMigrations()).toBe(false);
  });
});
