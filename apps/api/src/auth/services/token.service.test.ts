import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Repository } from 'typeorm';
import { FakeRepository } from '../../testing/fake-repo';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { RefreshToken } from '../entities/refresh-token.entity';
import type { GatewayTokenService } from './gateway-token.service';
import { TokenService } from './token.service';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const PUBLIC_KEY = '02'.padEnd(66, 'c');
const publicKeyByUserId = async (): Promise<string> => PUBLIC_KEY;

/**
 * Records the `(userId, familyId)` each mint was asked for — the binding this
 * suite asserts. The pseudonym's own storage is SQL, covered by
 * gateway-token.service.itest.ts against a real database.
 */
class RecordingGatewayTokens {
  readonly minted: Array<{ userId: string; familyId: string }> = [];

  async mintForFamily(userId: string, familyId: string): Promise<string> {
    this.minted.push({ userId, familyId });
    return this.minted.length.toString(16).padStart(64, '0');
  }
}

function asGatewayTokenService(recorder: RecordingGatewayTokens): GatewayTokenService {
  return recorder as unknown as GatewayTokenService;
}

describe('TokenService refresh rotation', () => {
  let clock: FakeClock;
  let repo: FakeRepository<RefreshToken>;
  let gatewayTokens: RecordingGatewayTokens;
  let service: TokenService;

  beforeEach(() => {
    clock = new FakeClock();
    repo = new FakeRepository<RefreshToken>();
    gatewayTokens = new RecordingGatewayTokens();
    service = new TokenService(
      new JwtService({ secret: 'test-secret', signOptions: { expiresIn: 900 } }),
      clock,
      new FakeEntropy(),
      asGatewayTokenService(gatewayTokens),
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

  it('mints the gateway pseudonym against the family the login started', async () => {
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);

    expect(pair.gatewayToken).not.toBe(pair.refreshToken);
    expect(pair.gatewayToken).not.toBe(pair.accessToken);
    expect(gatewayTokens.minted).toEqual([{ userId: USER_ID, familyId: repo.rows[0].familyId }]);
  });

  it('rotation re-mints the pseudonym into the same family, so it dies with the session', async () => {
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    const familyId = repo.rows[0].familyId;

    const rotated = await service.rotate(pair.refreshToken, publicKeyByUserId);

    expect(rotated.gatewayToken).not.toBe(pair.gatewayToken);
    expect(gatewayTokens.minted).toEqual([
      { userId: USER_ID, familyId },
      { userId: USER_ID, familyId },
    ]);
  });

  it('mints no pseudonym for a refresh it refuses', async () => {
    await expect(service.rotate('f'.repeat(64), publicKeyByUserId)).rejects.toThrow(
      UnauthorizedException
    );
    expect(gatewayTokens.minted).toHaveLength(0);
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

describe('TokenService scoped tokens', () => {
  const jwtService = new JwtService({ secret: 'test-secret', signOptions: { expiresIn: 900 } });

  function build(config: Record<string, string | undefined>): {
    service: TokenService;
    repo: FakeRepository<RefreshToken>;
  } {
    const repo = new FakeRepository<RefreshToken>();
    const service = new TokenService(
      jwtService,
      new FakeClock(),
      new FakeEntropy(),
      asGatewayTokenService(new RecordingGatewayTokens()),
      fakeConfig(config).service,
      repo as unknown as Repository<RefreshToken>
    );
    return { service, repo };
  }

  async function claims(accessToken: string): Promise<Record<string, number | string>> {
    return jwtService.verifyAsync(accessToken);
  }

  it('mints a verifiable token carrying the subject and scope, and no account publicKey', async () => {
    const { service } = build({});
    const scoped = await service.createScopedToken(USER_ID, 'device-approval');

    const decoded = await claims(scoped.accessToken);
    // The whole claim set, not a subset: the account pseudonym must not ride
    // along on a token whose holder has proven only control of an identity.
    expect(Object.keys(decoded).sort()).toEqual(['exp', 'iat', 'scope', 'sub']);
    expect(decoded.sub).toBe(USER_ID);
    expect(decoded.scope).toBe('device-approval');
    expect(decoded).not.toHaveProperty('publicKey');
  });

  it('carries no account publicKey even when a full session for the same user does', async () => {
    const { service } = build({});
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    const scoped = await service.createScopedToken(USER_ID, 'device-approval');

    expect(await claims(pair.accessToken)).toMatchObject({ publicKey: PUBLIC_KEY });
    expect(await claims(scoped.accessToken)).not.toHaveProperty('publicKey');
  });

  it('starts no refresh family — a capability cannot extend its own reach', async () => {
    const { service, repo } = build({});
    await service.createScopedToken(USER_ID, 'device-approval');
    expect(repo.rows).toHaveLength(0);
  });

  it('reports the TTL it actually signed, not the ambient access-token TTL', async () => {
    const { service } = build({});
    const scoped = await service.createScopedToken(USER_ID, 'device-approval');
    const { iat, exp } = await claims(scoped.accessToken);

    expect(scoped.expiresIn).toBe(600);
    expect(Number(exp) - Number(iat)).toBe(scoped.expiresIn);
  });

  it('honours SCOPED_TOKEN_TTL_SECONDS', async () => {
    const { service } = build({ SCOPED_TOKEN_TTL_SECONDS: '120' });
    const scoped = await service.createScopedToken(USER_ID, 'device-approval');
    const { iat, exp } = await claims(scoped.accessToken);

    expect(scoped.expiresIn).toBe(120);
    expect(Number(exp) - Number(iat)).toBe(120);
  });

  it('accepts the ceiling itself, so the bound is inclusive', async () => {
    const { service } = build({ SCOPED_TOKEN_TTL_SECONDS: '3600' });
    const scoped = await service.createScopedToken(USER_ID, 'device-approval');
    const { iat, exp } = await claims(scoped.accessToken);

    expect(scoped.expiresIn).toBe(3600);
    expect(Number(exp) - Number(iat)).toBe(3600);
  });

  it.each(['not-a-number', '0', '-60', '30.5', '', '3601', '86400'])(
    'falls back to the default TTL for the misconfigured value %j',
    async (raw) => {
      const { service } = build({ SCOPED_TOKEN_TTL_SECONDS: raw });
      const scoped = await service.createScopedToken(USER_ID, 'device-approval');
      const { iat, exp } = await claims(scoped.accessToken);

      expect(scoped.expiresIn).toBe(600);
      expect(Number(exp) - Number(iat)).toBe(600);
    }
  );

  it('leaves a full-session access token unscoped', async () => {
    const { service } = build({});
    const pair = await service.createTokenPair(USER_ID, PUBLIC_KEY);
    expect(await claims(pair.accessToken)).not.toHaveProperty('scope');
  });
});
