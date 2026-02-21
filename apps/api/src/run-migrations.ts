/**
 * Programmatic migration runner for Docker containers.
 *
 * The TypeORM CLI (via ts-node) is not available in production images.
 * This script runs migrations using compiled JS entities and migrations.
 *
 * Usage (inside Docker container):
 *   node dist/run-migrations.js
 */
import { DataSource } from 'typeorm';
import { config } from 'dotenv';

config();

const dataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_DATABASE || 'cipherbox',
  entities: ['dist/**/*.entity.js'],
  migrations: ['dist/migrations/*.js'],
  logging: ['error', 'migration'],
});

async function run() {
  try {
    await dataSource.initialize();
    console.log('Running migrations...');
    const migrations = await dataSource.runMigrations();
    if (migrations.length === 0) {
      console.log('No pending migrations.');
    } else {
      console.log(`Applied ${migrations.length} migration(s):`);
      for (const m of migrations) {
        console.log(`  - ${m.name}`);
      }
    }
    await dataSource.destroy();
    console.log('Migrations complete.');
    process.exit(0);
  } catch (error: unknown) {
    const err = error instanceof Error ? error : new Error(String(error));
    console.error(
      'Migration failed:',
      err.name || 'UnknownError',
      err.message?.replace(/(?:host|password|user(?:name)?)=[^\s;,]+/gi, '$&=***') || ''
    );
    process.exit(1);
  }
}

run();
