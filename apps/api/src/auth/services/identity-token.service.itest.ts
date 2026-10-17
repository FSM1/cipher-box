import { randomUUID } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { SpentIdentityToken } from '../entities/spent-identity-token.entity';
import { IdentityTokenService } from './identity-token.service';

/** The spent-row sweep against a REAL Postgres: its batch bound is a `ctid` subquery. */

const GRACE_MS = 60_000;

describe('IdentityTokenService sweep (real Postgres)', () => {
  let db: IntegrationDatabase;
  let spent: Repository<SpentIdentityToken>;

  beforeAll(async () => {
    db = await createIntegrationDatabase();
    spent = db.dataSource.getRepository(SpentIdentityToken);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await spent.clear();
  });

  function buildService(clock: FakeClock, env: Record<string, string> = {}): IdentityTokenService {
    return new IdentityTokenService(
      fakeConfig(env).service,
      clock,
      new FakeEntropy(),
      db.dataSource
    );
  }

  async function spend(expiresAt: Date): Promise<string> {
    const tokenId = randomUUID();
    await spent.insert({ tokenId, expiresAt });
    return tokenId;
  }

  it('sweeps the rows past their grace, and spares the rest', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const now = clock.now().getTime();
    const gone = await spend(new Date(now - GRACE_MS - 1));
    const inGrace = await spend(new Date(now - GRACE_MS + 1_000));
    const live = await spend(new Date(now + 1_000));

    expect(await service.sweepExpired()).toBe(1);
    expect(await spent.existsBy({ tokenId: gone })).toBe(false);
    expect(await spent.existsBy({ tokenId: inGrace })).toBe(true);
    expect(await spent.existsBy({ tokenId: live })).toBe(true);
  });

  it('walks past a full batch until nothing expired is left', async () => {
    const clock = new FakeClock();
    const service = buildService(clock, { SPENT_IDENTITY_TOKEN_SWEEP_BATCH_SIZE: '2' });
    const now = clock.now().getTime();
    for (let i = 0; i < 5; i += 1) {
      await spend(new Date(now - GRACE_MS - 1 - i));
    }

    expect(await service.sweepExpired()).toBe(5);
    expect(await spent.count()).toBe(0);
  });
});
