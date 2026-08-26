import { JwtService } from '@nestjs/jwt';
import { EntityManager, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sessionCredentialLockKey } from '../../common/advisory-lock';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { randomCompressedPublicKey } from '../../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { AcceleratorToken } from '../entities/accelerator-token.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { User } from '../entities/user.entity';
import { AcceleratorTokenService } from './accelerator-token.service';
import { TokenService } from './token.service';

/**
 * Rotation atomicity against a REAL Postgres: the property under test is that a
 * failure part-way through ROLLS BACK the single-use claim and every row written
 * beside it, which no in-memory repository can stand in for.
 */

const PUBLIC_KEY = '02'.padEnd(66, 'c');
const ACCELERATOR_TTL_MS = 900_000;
const publicKeyByUserId = async (): Promise<string> => PUBLIC_KEY;

/**
 * Writes its row on the caller's transaction like the real service, then throws
 * where a mid-mint database failure would while `fail` is set.
 */
class FlakyAcceleratorTokens {
  fail = false;
  private counter = 0;

  constructor(private readonly clock: FakeClock) {}

  async mintForFamily(userId: string, familyId: string, manager: EntityManager): Promise<string> {
    this.counter += 1;
    const tokenHash = this.counter.toString(16).padStart(64, '0');
    await manager.getRepository(AcceleratorToken).insert({
      userId,
      familyId,
      tokenHash,
      expiresAt: new Date(this.clock.now().getTime() + ACCELERATOR_TTL_MS),
    });
    if (this.fail) {
      throw new Error('accelerator mint unavailable');
    }
    return tokenHash;
  }
}

describe('TokenService rotation atomicity (real Postgres)', () => {
  let db: IntegrationDatabase;
  let refreshTokens: Repository<RefreshToken>;
  let acceleratorTokens: Repository<AcceleratorToken>;
  let users: Repository<User>;
  let accelerator: FlakyAcceleratorTokens;
  let service: TokenService;
  let userId: string;

  beforeAll(async () => {
    db = await createIntegrationDatabase();
    refreshTokens = db.dataSource.getRepository(RefreshToken);
    acceleratorTokens = db.dataSource.getRepository(AcceleratorToken);
    users = db.dataSource.getRepository(User);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  function buildService(env: Record<string, string> = {}): TokenService {
    return new TokenService(
      new JwtService({ secret: 'test-secret', signOptions: { expiresIn: 900 } }),
      new FakeClock(),
      new FakeEntropy(),
      accelerator as unknown as AcceleratorTokenService,
      fakeConfig(env).service,
      refreshTokens,
      db.dataSource
    );
  }

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
    accelerator = new FlakyAcceleratorTokens(new FakeClock());
    service = buildService();
    userId = (await users.save({ publicKey: randomCompressedPublicKey() })).id;
  });

  it('leaves the presented token unspent when the accelerator mint fails mid-rotation', async () => {
    const pair = await service.createTokenPair(userId, PUBLIC_KEY);
    const [presented] = await refreshTokens.find({ where: { userId } });

    accelerator.fail = true;
    await expect(service.rotate(pair.refreshToken, publicKeyByUserId)).rejects.toThrow(
      'accelerator mint unavailable'
    );

    // The claim rolled back with the failed mint, so the client's retry is a
    // first use rather than reuse detection — the family survives.
    const rows = await refreshTokens.find({ where: { userId } });
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(presented.id);
    expect(rows[0].usedAt).toBeNull();
    expect(await acceleratorTokens.count({ where: { userId } })).toBe(1);

    accelerator.fail = false;
    const rotated = await service.rotate(pair.refreshToken, publicKeyByUserId);
    expect(rotated.refreshToken).not.toBe(pair.refreshToken);
  });

  it('starts no half-family when a login mints its refresh row but not its pseudonym', async () => {
    await service.createTokenPair(userId, PUBLIC_KEY);

    accelerator.fail = true;
    await expect(service.createTokenPair(userId, PUBLIC_KEY)).rejects.toThrow(
      'accelerator mint unavailable'
    );

    expect(await refreshTokens.count({ where: { userId } })).toBe(1);
    expect(await acceleratorTokens.count({ where: { userId } })).toBe(1);
  });

  it('lets exactly one of two concurrent rotations win, and kills the family for the loser', async () => {
    const pair = await service.createTokenPair(userId, PUBLIC_KEY);

    const outcomes = await Promise.allSettled([
      service.rotate(pair.refreshToken, publicKeyByUserId),
      service.rotate(pair.refreshToken, publicKeyByUserId),
    ]);

    // One claims, one loses — and the loser's revocation COMMITS while its own
    // request fails, so nothing of the family survives either way.
    expect(outcomes.filter((o) => o.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter((o) => o.status === 'rejected')).toHaveLength(1);
    expect(await refreshTokens.count({ where: { userId } })).toBe(0);
  });

  it('revokes a successor a concurrent rotation commits while the family is being killed', async () => {
    const pair = await service.createTokenPair(userId, PUBLIC_KEY);
    const rotated = await service.rotate(pair.refreshToken, publicKeyByUserId);

    // Reuse of the spent token races the live successor's own rotation. Both
    // revocation and rotation take the account's lock, so the delete cannot
    // read a snapshot that predates a successor it must kill.
    await Promise.allSettled([
      service.rotate(pair.refreshToken, publicKeyByUserId),
      service.rotate(rotated.refreshToken, publicKeyByUserId),
    ]);

    expect(await refreshTokens.count({ where: { userId } })).toBe(0);
  });

  it('logs out everywhere even while a rotation is committing a successor', async () => {
    const pair = await service.createTokenPair(userId, PUBLIC_KEY);

    await Promise.allSettled([
      service.rotate(pair.refreshToken, publicKeyByUserId),
      service.revokeAllForUser(userId),
    ]);

    // Whichever order wins, no refresh row may outlive the logout: a rotation
    // that commits first is seen by the delete, and one that starts after finds
    // its claim gone and revokes what it made.
    expect(await refreshTokens.count({ where: { userId } })).toBe(0);
  });

  it('revokes a reused family even when the account lock is unavailable', async () => {
    // A thief who can contend the account's key must not be able to suppress
    // reuse detection: the revocation degrades, it never gets skipped.
    const contended = buildService({ DB_ADVISORY_LOCK_TIMEOUT_MS: '50' });
    const pair = await contended.createTokenPair(userId, PUBLIC_KEY);
    await contended.rotate(pair.refreshToken, publicKeyByUserId);

    const holder = db.dataSource.createQueryRunner();
    await holder.connect();
    await holder.startTransaction();
    try {
      await holder.query('SELECT pg_advisory_xact_lock($1::bigint)', [
        sessionCredentialLockKey(userId).toString(),
      ]);

      await expect(contended.rotate(pair.refreshToken, publicKeyByUserId)).rejects.toThrow(
        'Invalid refresh token'
      );
      expect(await refreshTokens.count({ where: { userId } })).toBe(0);
    } finally {
      await holder.rollbackTransaction();
      await holder.release();
    }
  });
});
