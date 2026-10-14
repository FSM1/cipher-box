import { DataSource, MigrationInterface } from 'typeorm';
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

  async function recordedNames(ds: DataSource): Promise<string[]> {
    const rows: { name: string }[] = await ds.query('SELECT name FROM migrations');
    return rows.map((row) => row.name).sort();
  }

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
    expect(await recordedNames(db.dataSource)).toEqual(expected);
    expect(await db.dataSource.showMigrations()).toBe(false);
  });

  it('lets a waiting runner proceed after the holder fails', async () => {
    db = await createIntegrationDatabase({ migrate: false });
    const expected = db.dataSource.migrations.map((migration) => migration.name).sort();
    let reached!: () => void;
    let fail!: () => void;
    const holding = new Promise<void>((resolve) => (reached = resolve));
    const failNow = new Promise<void>((resolve) => (fail = resolve));
    // Sorts first, so the holder fails before it applies anything.
    class FailFirst1000000000000 implements MigrationInterface {
      name = 'FailFirst1000000000000';
      async up(): Promise<void> {
        reached();
        await failNow;
        throw new Error('the holder migration fails');
      }
      async down(): Promise<void> {}
    }
    second = new DataSource({
      ...db.dataSource.options,
      migrations: [FailFirst1000000000000, ...(db.dataSource.options.migrations as never[])],
    });
    await second.initialize();

    const holder = runMigrationsLocked(second);
    await holding;
    let waiterDone = false;
    const waiter = runMigrationsLocked(db.dataSource).finally(() => (waiterDone = true));
    await new Promise((resolve) => setTimeout(resolve, 600));
    expect(waiterDone).toBe(false);

    fail();
    await expect(holder).rejects.toThrow('the holder migration fails');
    expect(await waiter).toHaveLength(expected.length);
    expect(await recordedNames(db.dataSource)).toEqual(expected);
  });
});
