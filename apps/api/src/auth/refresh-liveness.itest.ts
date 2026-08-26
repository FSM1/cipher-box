import { randomUUID } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomCompressedPublicKey } from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { liveRefreshRowSql, refreshRowState } from './refresh-liveness';

/**
 * The two readings of one rule, run against the same rows in a real Postgres:
 * the TypeScript classifier rotation uses, and the SQL predicate the accelerator
 * verify path joins on. This suite is the reason the rule can only have one home
 * — it fails the moment the two disagree.
 */

const NOW = new Date('2026-01-01T00:00:00Z');
const HOUR_MS = 60 * 60 * 1000;

const CASES: Array<{ name: string; usedAt: Date | null; expiresAt: Date }> = [
  {
    name: 'unspent and far from expiry',
    usedAt: null,
    expiresAt: new Date(NOW.getTime() + HOUR_MS),
  },
  {
    name: 'unspent, one millisecond from expiry',
    usedAt: null,
    expiresAt: new Date(NOW.getTime() + 1),
  },
  { name: 'unspent, expiring exactly now', usedAt: null, expiresAt: NOW },
  {
    name: 'unspent, one millisecond past expiry',
    usedAt: null,
    expiresAt: new Date(NOW.getTime() - 1),
  },
  { name: 'spent but unexpired', usedAt: NOW, expiresAt: new Date(NOW.getTime() + HOUR_MS) },
  { name: 'spent and expired', usedAt: NOW, expiresAt: new Date(NOW.getTime() - HOUR_MS) },
  {
    name: 'spent in the future',
    usedAt: new Date(NOW.getTime() + 1),
    expiresAt: new Date(NOW.getTime() + HOUR_MS),
  },
];

describe('refresh-family liveness (real Postgres)', () => {
  let db: IntegrationDatabase;
  let refreshTokens: Repository<RefreshToken>;
  let users: Repository<User>;
  let userId: string;

  beforeAll(async () => {
    db = await createIntegrationDatabase();
    refreshTokens = db.dataSource.getRepository(RefreshToken);
    users = db.dataSource.getRepository(User);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
    userId = (await users.save({ publicKey: randomCompressedPublicKey() })).id;
  });

  it.each(CASES)('agrees on a row $name', async ({ usedAt, expiresAt }) => {
    const row = await refreshTokens.save({
      userId,
      familyId: randomUUID(),
      tokenHash: randomUUID().replace(/-/g, '').padEnd(64, '0'),
      expiresAt,
      usedAt,
    });

    const bySql = await refreshTokens
      .createQueryBuilder('refresh')
      .where('refresh.id = :id', { id: row.id })
      .andWhere(liveRefreshRowSql('refresh'))
      .setParameter('now', NOW)
      .getCount();

    expect(bySql === 1).toBe(refreshRowState(row, NOW) === 'live');
  });

  it('refuses an alias that is not a bare identifier', () => {
    expect(() => liveRefreshRowSql('refresh; DROP TABLE users --')).toThrow(/Invalid SQL alias/);
  });
});
