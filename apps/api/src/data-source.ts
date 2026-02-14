/**
 * TypeORM Data Source configuration for CLI migrations.
 *
 * This file is used by the TypeORM CLI to run migrations.
 * It's separate from the NestJS TypeORM module configuration in app.module.ts.
 *
 * Usage:
 *   pnpm --filter @cipherbox/api typeorm migration:run -d src/data-source.ts
 *   pnpm --filter @cipherbox/api typeorm migration:revert -d src/data-source.ts
 */
import { DataSource } from 'typeorm';
import { config } from 'dotenv';

// Load environment variables
config();

export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_DATABASE || 'cipherbox',
  entities: ['src/**/*.entity.ts'],
  migrations: ['src/migrations/*.ts'],
  logging: process.env.NODE_ENV === 'development',
});
