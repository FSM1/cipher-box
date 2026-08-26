import { randomUUID } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sha256Hex } from '../../common/hash';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { randomCompressedPublicKey } from '../../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { AcceleratorToken } from '../entities/accelerator-token.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { User } from '../entities/user.entity';
import { AcceleratorTokenService, REFUSAL_CACHE_MAX_ENTRIES } from './accelerator-token.service';

/**
 * The accelerator pseudonym against a REAL Postgres: its validity is a join
 * against the refresh family, and its rotation sweep is a DELETE — neither is
 * anything an in-memory repository could stand in for.
 */

const ACCESS_TTL_SECONDS = 900;
const CACHE_TTL_SECONDS = 30;
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;

describe('AcceleratorTokenService (real Postgres)', () => {
  let db: IntegrationDatabase;
  let acceleratorTokens: Repository<AcceleratorToken>;
  let refreshTokens: Repository<RefreshToken>;
  let users: Repository<User>;

  beforeAll(async () => {
    db = await createIntegrationDatabase();
    acceleratorTokens = db.dataSource.getRepository(AcceleratorToken);
    refreshTokens = db.dataSource.getRepository(RefreshToken);
    users = db.dataSource.getRepository(User);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
  });

  function buildService(
    clock: FakeClock,
    env: Record<string, string> = {}
  ): AcceleratorTokenService {
    return new AcceleratorTokenService(
      clock,
      new FakeEntropy(),
      fakeConfig({
        ACCESS_TOKEN_TTL_SECONDS: String(ACCESS_TTL_SECONDS),
        ACCELERATOR_TOKEN_CACHE_TTL_SECONDS: String(CACHE_TTL_SECONDS),
        ...env,
      }).service,
      acceleratorTokens
    );
  }

  /**
   * A live session: one unused refresh row in a fresh family, on a new account
   * unless `userId` names an existing one.
   */
  async function startSession(
    clock: FakeClock,
    userId?: string,
    reviveFamilyId?: string
  ): Promise<{ userId: string; familyId: string }> {
    const owner = userId ?? (await users.save({ publicKey: randomCompressedPublicKey() })).id;
    const familyId = reviveFamilyId ?? randomUUID();
    await refreshTokens.save({
      userId: owner,
      familyId,
      tokenHash: randomUUID().replace(/-/g, '').padEnd(64, '0'),
      expiresAt: new Date(clock.now().getTime() + REFRESH_TTL_MS),
      usedAt: null,
    });
    return { userId: owner, familyId };
  }

  it('mints an opaque token that carries nothing about the account', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);

    const token = await service.mintForFamily(userId, familyId, db.dataSource.manager);

    expect(token).toMatch(/^[0-9a-f]{64}$/);
    const [row] = await acceleratorTokens.find({ where: { userId } });
    // The digest, not merely something other than the raw token.
    expect(row.tokenHash).toBe(sha256Hex(token));
    expect(row.expiresAt.getTime()).toBe(clock.now().getTime() + ACCESS_TTL_SECONDS * 1000);
    expect(await service.verify(token)).toBe(true);
  });

  it('refuses anything that is not the minted shape without touching the row', async () => {
    const service = buildService(new FakeClock());

    for (const candidate of ['', 'not-hex', 'F'.repeat(64), 'a'.repeat(63), 'a'.repeat(65)]) {
      expect(await service.verify(candidate)).toBe(false);
    }
  });

  it('refuses a well-formed token it never minted', async () => {
    const service = buildService(new FakeClock());
    expect(await service.verify('b'.repeat(64))).toBe(false);
  });

  it('rotation replaces the family pseudonym and retires the previous one', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);

    const first = await service.mintForFamily(userId, familyId, db.dataSource.manager);
    const second = await service.mintForFamily(userId, familyId, db.dataSource.manager);

    expect(second).not.toBe(first);
    expect(await acceleratorTokens.count({ where: { userId } })).toBe(1);
    expect(await service.verify(second)).toBe(true);
    expect(await service.verify(first)).toBe(false);
  });

  it('leaves other sessions of the same account alone', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const other = await startSession(clock, userId);

    const otherToken = await service.mintForFamily(userId, other.familyId, db.dataSource.manager);
    await service.mintForFamily(userId, familyId, db.dataSource.manager);

    expect(await service.verify(otherToken)).toBe(true);
  });

  it('sweeps the account’s expired rows on the next mint', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const abandoned = await startSession(clock);
    await service.mintForFamily(abandoned.userId, abandoned.familyId, db.dataSource.manager);

    clock.advanceMs(ACCESS_TTL_SECONDS * 1000 + 1);
    const relogin = await startSession(clock, abandoned.userId);
    await service.mintForFamily(relogin.userId, relogin.familyId, db.dataSource.manager);

    expect(await acceleratorTokens.count({ where: { userId: abandoned.userId } })).toBe(1);
  });

  it('sweeps every account’s expired rows on a tick, and spares the live ones', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const abandoned = await startSession(clock);
    await service.mintForFamily(abandoned.userId, abandoned.familyId, db.dataSource.manager);

    clock.advanceMs(ACCESS_TTL_SECONDS * 1000 + 1);
    const active = await startSession(clock);
    await service.mintForFamily(active.userId, active.familyId, db.dataSource.manager);

    // No mint by the abandoned account: only the scheduled sweep can reclaim it.
    expect(await service.sweepExpired()).toBe(1);
    expect(await acceleratorTokens.count({ where: { userId: abandoned.userId } })).toBe(0);
    expect(await acceleratorTokens.count({ where: { userId: active.userId } })).toBe(1);
  });

  it('walks past a full batch until nothing expired is left', async () => {
    const clock = new FakeClock();
    const service = buildService(clock, { ACCELERATOR_TOKEN_SWEEP_BATCH_SIZE: '2' });
    for (let i = 0; i < 5; i += 1) {
      const session = await startSession(clock);
      await service.mintForFamily(session.userId, session.familyId, db.dataSource.manager);
    }
    clock.advanceMs(ACCESS_TTL_SECONDS * 1000 + 1);

    expect(await service.sweepExpired()).toBe(5);
    expect(await acceleratorTokens.count()).toBe(0);
  });

  it('stops verifying once the session it names is gone', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId, db.dataSource.manager);

    // What logout and reuse detection both do: hard-delete the family.
    await refreshTokens.delete({ familyId });

    expect(await service.verify(token)).toBe(false);
    // The row itself outlives the session; only the join makes it worthless.
    expect(await acceleratorTokens.count({ where: { userId } })).toBe(1);
  });

  it('stops verifying once every refresh row in the family has been spent', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId, db.dataSource.manager);

    await refreshTokens.update({ familyId }, { usedAt: clock.now() });

    expect(await service.verify(token)).toBe(false);
  });

  it('dies with the account, by cascade', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId, db.dataSource.manager);

    await users.delete({ id: userId });

    expect(await service.verify(token)).toBe(false);
    expect(await acceleratorTokens.count({ where: { userId } })).toBe(0);
  });

  it('serves a verified token from cache, and re-reads once the entry ages out', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId, db.dataSource.manager);
    expect(await service.verify(token)).toBe(true);

    await refreshTokens.delete({ familyId });

    // Revocation lands at cache expiry, not before — the decision's stated bound.
    expect(await service.verify(token)).toBe(true);
    clock.advanceMs(CACHE_TTL_SECONDS * 1000 + 1);
    expect(await service.verify(token)).toBe(false);
  });

  it('never trusts a cache entry past the token’s own expiry', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId, db.dataSource.manager);

    clock.advanceMs(ACCESS_TTL_SECONDS * 1000 - 1);
    expect(await service.verify(token)).toBe(true);
    // The cache window would still be open here; the token's expiry is not.
    clock.advanceMs(2);
    expect(await service.verify(token)).toBe(false);
  });

  it('spends its refusal budget on refusals alone, never on a live session', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const live = await startSession(clock);
    const revoked = await startSession(clock);

    const liveToken = await service.mintForFamily(
      live.userId,
      live.familyId,
      db.dataSource.manager
    );
    expect(await service.verify(liveToken)).toBe(true);
    const revokedToken = await service.mintForFamily(
      revoked.userId,
      revoked.familyId,
      db.dataSource.manager
    );
    await refreshTokens.delete({ familyId: revoked.familyId });
    expect(await service.verify(revokedToken)).toBe(false);

    // A spray of invented tokens, one past the refusal budget. These keys are
    // the attacker's to choose, so they must cost only each other.
    for (let i = 0; i <= REFUSAL_CACHE_MAX_ENTRIES; i += 1) {
      await service.verify(sha256Hex(String(i)));
    }

    // The spray pushed the earlier refusal out of its own budget: restoring the
    // session behind it is seen, which a still-cached refusal would have hidden.
    await startSession(clock, revoked.userId, revoked.familyId);
    expect(await service.verify(revokedToken)).toBe(true);

    // The acceptance, meanwhile, is untouched — revoked underneath, so only the
    // surviving cache entry can still answer true.
    await refreshTokens.delete({ familyId: live.familyId });
    expect(await service.verify(liveToken)).toBe(true);
  });

  it('caches a refusal, and ages it out far sooner than an acceptance', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId, db.dataSource.manager);

    await refreshTokens.delete({ familyId });
    expect(await service.verify(token)).toBe(false);

    await refreshTokens.save({
      userId,
      familyId,
      tokenHash: randomUUID().replace(/-/g, '').padEnd(64, 'a'),
      expiresAt: new Date(clock.now().getTime() + REFRESH_TTL_MS),
      usedAt: null,
    });
    expect(await service.verify(token)).toBe(false);

    clock.advanceMs(1001);
    expect(await service.verify(token)).toBe(true);
  });
});
