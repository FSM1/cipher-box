import { randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import { AuthMethod } from '../auth/entities/auth-method.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { User } from '../auth/entities/user.entity';
import { MailboxMessage } from '../mailbox/entities/mailbox-message.entity';
import { AddMailboxMessages1784519962991 } from '../migrations/1784519962991-AddMailboxMessages';
import { AddNameInventoryAndPinnedCids1784566605863 } from '../migrations/1784566605863-AddNameInventoryAndPinnedCids';
import { InitAuthSchema1784513040045 } from '../migrations/1784513040045-InitAuthSchema';
import { NameInventory } from '../registry/entities/name-inventory.entity';
import { PinnedCid } from '../registry/entities/pinned-cid.entity';

/**
 * Standard DB_* env, defaulting to docker/docker-compose.yml. Only the admin
 * database is fixed; every suite's working database is minted fresh.
 */
const DB = {
  host: process.env.DB_HOST ?? 'localhost',
  port: Number(process.env.DB_PORT ?? 5432),
  username: process.env.DB_USERNAME ?? 'postgres',
  password: process.env.DB_PASSWORD ?? 'postgres',
};

// The full application schema — every entity + every committed migration — so a
// throwaway database is a faithful copy of production regardless of which tables
// a given suite touches.
const ENTITIES = [User, AuthMethod, RefreshToken, NameInventory, PinnedCid, MailboxMessage];
const MIGRATIONS = [
  InitAuthSchema1784513040045,
  AddMailboxMessages1784519962991,
  AddNameInventoryAndPinnedCids1784566605863,
];

export interface IntegrationDatabase {
  dataSource: DataSource;
  name: string;
  /** Destroy the pool and drop ONLY this run's database. */
  teardown: () => Promise<void>;
}

export interface IntegrationDatabaseOptions {
  /** Pool ceiling; small values make advisory-lock pool-saturation cheap to prove. */
  poolMax?: number;
}

/** One-off admin DDL via a short-lived connection to the default `postgres` database. */
async function adminExec(sql: string): Promise<void> {
  const admin = new DataSource({ type: 'postgres', ...DB, database: 'postgres' });
  await admin.initialize();
  try {
    await admin.query(sql);
  } finally {
    await admin.destroy();
  }
}

/**
 * Provision a randomized, exclusively-owned throwaway database, migrate the full
 * schema into it, and hand back a ready DataSource. The name carries a
 * `crypto.randomUUID()` suffix so it can never collide with a shared dev database
 * or another concurrent run, and teardown force-drops ONLY that name — a fixed
 * shared database is never touched (Greptile P2 on #683).
 */
export async function createIntegrationDatabase(
  options: IntegrationDatabaseOptions = {}
): Promise<IntegrationDatabase> {
  const name = `cipherbox_it_${randomUUID().replace(/-/g, '')}`;
  await adminExec(`CREATE DATABASE "${name}"`);

  const dataSource = new DataSource({
    type: 'postgres',
    ...DB,
    database: name,
    entities: ENTITIES,
    migrations: MIGRATIONS,
    synchronize: false,
    uuidExtension: 'pgcrypto',
    extra: options.poolMax ? { max: options.poolMax } : undefined,
  });

  try {
    await dataSource.initialize();
    await dataSource.runMigrations();
  } catch (error) {
    if (dataSource.isInitialized) {
      await dataSource.destroy();
    }
    await adminExec(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    throw error;
  }

  return {
    dataSource,
    name,
    async teardown() {
      if (dataSource.isInitialized) {
        await dataSource.destroy();
      }
      // FORCE only ever targets this run's randomized, exclusively-owned name.
      await adminExec(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    },
  };
}
