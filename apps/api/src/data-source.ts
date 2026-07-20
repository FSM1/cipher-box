/**
 * TypeORM DataSource for CLI migrations (migration:run / migration:generate
 * / the CI drift check). Separate from the NestJS TypeORM wiring in
 * app.module.ts.
 */
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
  entities: ['src/**/*.entity.ts'],
  migrations: ['src/migrations/*.ts'],
  uuidExtension: 'pgcrypto',
  logging: false,
});
