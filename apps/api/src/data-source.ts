/**
 * TypeORM DataSource for CLI migrations (migration:run / migration:generate
 * / the CI drift check) and for the deployed image's `run-migrations`.
 * Separate from the NestJS TypeORM wiring in app.module.ts.
 */
import { join } from 'node:path';
import { config } from 'dotenv';
import { DataSource } from 'typeorm';

config();

export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST ?? 'localhost',
  port: Number(process.env.DB_PORT ?? 5432),
  username: process.env.DB_USERNAME ?? 'postgres',
  password: process.env.DB_PASSWORD ?? 'postgres',
  database: process.env.DB_DATABASE ?? 'cipherbox',
  // Resolved beside this file, so the ts-node CLI walks `src` and the compiled
  // runner walks `dist`.
  entities: [join(__dirname, '**/*.entity.{ts,js}')],
  migrations: [join(__dirname, 'migrations/*.{ts,js}')],
  // Per-migration transaction: each migration wraps in its own txn by default,
  // so a migration may opt out (transaction = false) to run CONCURRENTLY DDL.
  migrationsTransactionMode: 'each',
  uuidExtension: 'pgcrypto',
  logging: false,
});
