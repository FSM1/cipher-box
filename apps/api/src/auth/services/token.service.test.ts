import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Repository } from 'typeorm';
import { FakeRepository } from '../../testing/fake-repo';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { RefreshToken } from '../entities/refresh-token.entity';
import { TokenService } from './token.service';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const PUBLIC_KEY = '02'.padEnd(66, 'c');
const publicKeyByUserId = async (): Promise<string> => PUBLIC_KEY;

describe('TokenService refresh rotation', () => {
  let clock: FakeClock;
  let repo: FakeRepository<RefreshToken>;
  let service: TokenService;

  beforeEach(() => {
    clock = new FakeClock();
    repo = new FakeRepository<RefreshToken>();
    service = new TokenService(
      new JwtService({ secret: 'test-secret', signOptions: { expiresIn: 900 } }),
      clock,
      new FakeEntropy(),
      fakeConfig({}).service,
      repo as unknown as Repository<RefreshToken>
    );
  });

  it('creates a pair whose refresh token is stored only as a hash', async () => {
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    expect(pair.accessToken.split('.')).toHaveLength(3);
    expect(pair.refreshToken).toMatch(/^[0-9a-f]{64}$/);
    expect(repo.rows).toHaveLength(1);
    expect(repo.rows[0].tokenHash).not.toBe(pair.refreshToken);
    expect(repo.rows[0].usedAt).toBeNull();
  });

  it('rotates: old token becomes used, successor joins the same family', async () => {
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    const familyId = repo.rows[0].familyId;

    const rotated = await service.rotate(pair.refreshToken, publicKeyByUserId);
    expect(rotated.refreshToken).not.toBe(pair.refreshToken);
    expect(repo.rows).toHaveLength(2);
    expect(repo.rows.every((row) => row.familyId === familyId)).toBe(true);
    expect(repo.rows[0].usedAt).not.toBeNull();
    expect(repo.rows[1].usedAt).toBeNull();
  });

  it('reuse of a rotated token hard-deletes the whole family', async () => {
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    await service.rotate(pair.refreshToken, publicKeyByUserId);

    await expect(service.rotate(pair.refreshToken, publicKeyByUserId)).rejects.toThrow(
      UnauthorizedException
    );
    expect(repo.rows).toHaveLength(0);
  });

  it('rejects an expired token and clears its family', async () => {
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    clock.advanceMs(7 * 24 * 60 * 60 * 1000 + 1);

    await expect(service.rotate(pair.refreshToken, publicKeyByUserId)).rejects.toThrow(
      UnauthorizedException
    );
    expect(repo.rows).toHaveLength(0);
  });

  it('rejects a token it never issued', async () => {
    await expect(service.rotate('f'.repeat(64), publicKeyByUserId)).rejects.toThrow(
      UnauthorizedException
    );
  });

  it('rotation sweeps out the user’s expired rows', async () => {
    await service.createTokenPair(USER_ID, PUBLIC_KEY);
    clock.advanceMs(8 * 24 * 60 * 60 * 1000); // first family is now expired

    const fresh = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    const freshFamilyId = repo.rows[1].familyId;
    expect(repo.rows).toHaveLength(2);

    await service.rotate(fresh.refreshToken, publicKeyByUserId);
    // Expired row purged; only the fresh family (used + successor) remains.
    expect(repo.rows).toHaveLength(2);
    expect(repo.rows.every((row) => row.familyId === freshFamilyId)).toBe(true);
  });

  it('revokeAllForUser hard-deletes every row', async () => {
    await service.createTokenPair(USER_ID, PUBLIC_KEY);
    await service.createTokenPair(USER_ID, PUBLIC_KEY);
    expect(repo.rows).toHaveLength(2);

    await service.revokeAllForUser(USER_ID);
    expect(repo.rows).toHaveLength(0);
  });
});
