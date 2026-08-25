import { randomUUID } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sha256Hex } from '../../common/hash';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { randomCompressedPublicKey } from '../../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { GatewayToken } from '../entities/gateway-token.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { User } from '../entities/user.entity';
import { GatewayTokenService, REFUSAL_CACHE_MAX_ENTRIES } from './gateway-token.service';

/**
 * The accelerator pseudonym against a REAL Postgres: its validity is a join
 * against the refresh family, and its rotation sweep is a DELETE — neither is
 * anything an in-memory repository could stand in for.
 */

const ACCESS_TTL_SECONDS = 900;
const CACHE_TTL_SECONDS = 30;
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;

describe('GatewayTokenService (real Postgres)', () => {
  let db: IntegrationDatabase;
  let gatewayTokens: Repository<GatewayToken>;
  let refreshTokens: Repository<RefreshToken>;
  let users: Repository<User>;

  beforeAll(async () => {
    db = await createIntegrationDatabase();
    gatewayTokens = db.dataSource.getRepository(GatewayToken);
    refreshTokens = db.dataSource.getRepository(RefreshToken);
    users = db.dataSource.getRepository(User);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
  });

  function buildService(clock: FakeClock): GatewayTokenService {
    return new GatewayTokenService(
      clock,
      new FakeEntropy(),
      fakeConfig({
        ACCESS_TOKEN_TTL_SECONDS: String(ACCESS_TTL_SECONDS),
        GATEWAY_TOKEN_CACHE_TTL_SECONDS: String(CACHE_TTL_SECONDS),
      }).service,
      gatewayTokens
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

    const token = await service.mintForFamily(userId, familyId);

    expect(token).toMatch(/^[0-9a-f]{64}$/);
    const [row] = await gatewayTokens.find({ where: { userId } });
    expect(row.tokenHash).not.toBe(token);
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

    const first = await service.mintForFamily(userId, familyId);
    const second = await service.mintForFamily(userId, familyId);

    expect(second).not.toBe(first);
    expect(await gatewayTokens.count({ where: { userId } })).toBe(1);
    expect(await service.verify(second)).toBe(true);
    expect(await service.verify(first)).toBe(false);
  });

  it('leaves other sessions of the same account alone', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const other = await startSession(clock, userId);

    const otherToken = await service.mintForFamily(userId, other.familyId);
    await service.mintForFamily(userId, familyId);

    expect(await service.verify(otherToken)).toBe(true);
  });

  it('sweeps the account’s expired rows on the next mint', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const abandoned = await startSession(clock);
    await service.mintForFamily(abandoned.userId, abandoned.familyId);

    clock.advanceMs(ACCESS_TTL_SECONDS * 1000 + 1);
    const relogin = await startSession(clock, abandoned.userId);
    await service.mintForFamily(relogin.userId, relogin.familyId);

    expect(await gatewayTokens.count({ where: { userId: abandoned.userId } })).toBe(1);
  });

  it('stops verifying once the session it names is gone', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId);

    // What logout and reuse detection both do: hard-delete the family.
    await refreshTokens.delete({ familyId });

    expect(await service.verify(token)).toBe(false);
    // The row itself outlives the session; only the join makes it worthless.
    expect(await gatewayTokens.count({ where: { userId } })).toBe(1);
  });

  it('stops verifying once every refresh row in the family has been spent', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId);

    await refreshTokens.update({ familyId }, { usedAt: clock.now() });

    expect(await service.verify(token)).toBe(false);
  });

  it('dies with the account, by cascade', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId);

    await users.delete({ id: userId });

    expect(await service.verify(token)).toBe(false);
    expect(await gatewayTokens.count({ where: { userId } })).toBe(0);
  });

  it('serves a verified token from cache, and re-reads once the entry ages out', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId);
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
    const token = await service.mintForFamily(userId, familyId);

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

    const liveToken = await service.mintForFamily(live.userId, live.familyId);
    expect(await service.verify(liveToken)).toBe(true);
    const revokedToken = await service.mintForFamily(revoked.userId, revoked.familyId);
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
    const token = await service.mintForFamily(userId, familyId);

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
