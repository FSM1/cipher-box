import { secp256k1 } from '@noble/curves/secp256k1';
import { randomUUID } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { GatewayToken } from '../entities/gateway-token.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { User } from '../entities/user.entity';
import { GatewayTokenService } from './gateway-token.service';

/**
 * The accelerator pseudonym against a REAL Postgres: its validity is a join
 * against the refresh family, and its rotation sweep is a DELETE — neither is
 * anything an in-memory repository could stand in for.
 */

const ACCESS_TTL_SECONDS = 900;
const CACHE_TTL_SECONDS = 30;
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function compressedPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
  }
}

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

  /** A live session: an account plus one unused refresh row in a fresh family. */
  async function startSession(clock: FakeClock): Promise<{ userId: string; familyId: string }> {
    const user = await users.save({ publicKey: compressedPublicKey() });
    const familyId = randomUUID();
    await refreshTokens.save({
      userId: user.id,
      familyId,
      tokenHash: randomUUID().replace(/-/g, '').padEnd(64, '0'),
      expiresAt: new Date(clock.now().getTime() + REFRESH_TTL_MS),
      usedAt: null,
    });
    return { userId: user.id, familyId };
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

  it('expires with the access token', async () => {
    const clock = new FakeClock();
    const service = buildService(clock);
    const { userId, familyId } = await startSession(clock);
    const token = await service.mintForFamily(userId, familyId);

    clock.advanceMs(ACCESS_TTL_SECONDS * 1000 + 1);

    expect(await service.verify(token)).toBe(false);
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
    const other = await refreshTokens.save({
      userId,
      familyId: randomUUID(),
      tokenHash: randomUUID().replace(/-/g, '').padEnd(64, '1'),
      expiresAt: new Date(clock.now().getTime() + REFRESH_TTL_MS),
      usedAt: null,
    });

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
    const relogin = randomUUID();
    await refreshTokens.save({
      userId: abandoned.userId,
      familyId: relogin,
      tokenHash: randomUUID().replace(/-/g, '').padEnd(64, '2'),
      expiresAt: new Date(clock.now().getTime() + REFRESH_TTL_MS),
      usedAt: null,
    });
    await service.mintForFamily(abandoned.userId, relogin);

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
    clock.advanceMs(service.revocationLatencyMs + 1);
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
});
