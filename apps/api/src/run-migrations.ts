/**
 * Migration runner for the deployed image: `node dist/run-migrations.js`.
 * The TypeORM CLI needs ts-node, which the production image does not carry.
 */
import dataSource from './data-source';

async function run(): Promise<void> {
  await dataSource.initialize();
  const applied = await dataSource.runMigrations();
  console.log(
    applied.length === 0
      ? 'No pending migrations.'
      : `Applied ${applied.length} migration(s): ${applied.map((m) => m.name).join(', ')}`
  );
  await dataSource.destroy();
}

run().catch((error: unknown) => {
  console.error(`Migration failed: ${String(error)}`);
  process.exit(1);
});
