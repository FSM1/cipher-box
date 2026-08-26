import { JwtService } from '@nestjs/jwt';
import { EntityManager, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
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
  let gateway: FlakyAcceleratorTokens;
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

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
    gateway = new FlakyAcceleratorTokens(new FakeClock());
    service = new TokenService(
      new JwtService({ secret: 'test-secret', signOptions: { expiresIn: 900 } }),
      new FakeClock(),
      new FakeEntropy(),
      gateway as unknown as AcceleratorTokenService,
      fakeConfig({}).service,
      refreshTokens,
      db.dataSource
    );
    userId = (await users.save({ publicKey: randomCompressedPublicKey() })).id;
  });

  it('leaves the presented token unspent when the accelerator mint fails mid-rotation', async () => {
    const pair = await service.createTokenPair(userId, PUBLIC_KEY);
    const [presented] = await refreshTokens.find({ where: { userId } });

    gateway.fail = true;
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

    gateway.fail = false;
    const rotated = await service.rotate(pair.refreshToken, publicKeyByUserId);
    expect(rotated.refreshToken).not.toBe(pair.refreshToken);
  });

  it('starts no half-family when a login mints its refresh row but not its pseudonym', async () => {
    await service.createTokenPair(userId, PUBLIC_KEY);

    gateway.fail = true;
    await expect(service.createTokenPair(userId, PUBLIC_KEY)).rejects.toThrow(
      'accelerator mint unavailable'
    );

    expect(await refreshTokens.count({ where: { userId } })).toBe(1);
    expect(await acceleratorTokens.count({ where: { userId } })).toBe(1);
  });

  it('still hard-deletes the family when a rotation is refused as reuse', async () => {
    const pair = await service.createTokenPair(userId, PUBLIC_KEY);
    await service.rotate(pair.refreshToken, publicKeyByUserId);

    // The revocation must COMMIT while the request fails.
    await expect(service.rotate(pair.refreshToken, publicKeyByUserId)).rejects.toThrow(
      'Invalid refresh token'
    );
    expect(await refreshTokens.count({ where: { userId } })).toBe(0);
  });
});
