"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
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
const typeorm_1 = require("typeorm");
const dotenv_1 = require("dotenv");
// Load environment variables
(0, dotenv_1.config)();
exports.default = new typeorm_1.DataSource({
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
//# sourceMappingURL=data-source.js.map