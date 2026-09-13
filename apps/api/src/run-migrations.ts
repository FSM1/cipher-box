/**
 * Migration runner for the deployed image: `node dist/run-migrations.js`.
 * The TypeORM CLI needs ts-node, which the production image does not carry.
 */
import dataSource from './data-source';

async function run(): Promise<void> {
  await dataSource.initialize();
  try {
    const applied = await dataSource.runMigrations();
    if (applied.length === 0) {
      console.log('No pending migrations.');
    } else {
      console.log(
        `Applied ${applied.length} migration(s): ${applied.map((m) => m.name).join(', ')}`
      );
    }
  } finally {
    await dataSource.destroy();
  }
}

run().catch((error: unknown) => {
  const err = error instanceof Error ? error : new Error(String(error));
  console.error(`Migration failed: ${err.name}: ${err.message}`);
  process.exit(1);
});
