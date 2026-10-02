import * as jose from 'jose';
import { randomUUID } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { FakeClock } from '../../testing/fakes';
import {
  bootedIdentityTokenService as bootedService,
  encodedIdentitySigningKey,
  identityTokenWithJti,
  identityTokenWithRawExp,
} from '../../testing/identity-tokens';
import {
  IDENTITY_TOKEN_AUDIENCE,
  IDENTITY_TOKEN_ISSUER,
  IdentityTokenService,
} from './identity-token.service';

/** The verification key a Web3Auth custom verifier would build from the JWKS. */
async function verificationKeyFrom(service: IdentityTokenService) {
  const [jwk] = service.jwks().keys;
  return jose.importJWK(jwk, 'RS256');
}

describe('IdentityTokenService', () => {
  let encodedPem: string;

  beforeAll(() => {
    encodedPem = encodedIdentitySigningKey();
  });

  it('refuses to boot without a signing key in any deployed environment', async () => {
    await expect(bootedService({ NODE_ENV: 'production' })).rejects.toThrow(
      /IDENTITY_JWT_PRIVATE_KEY is required/
    );
    await expect(bootedService({ NODE_ENV: 'staging' })).rejects.toThrow(
      /IDENTITY_JWT_PRIVATE_KEY is required/
    );
  });

  it('boots on an ephemeral key only in development and test', async () => {
    await expect(bootedService({ NODE_ENV: 'development' })).resolves.toBeDefined();
    await expect(bootedService({ NODE_ENV: 'test' })).resolves.toBeDefined();
  });

  it('serves only the public half — no private RSA field reaches the JWKS', async () => {
    const service = await bootedService({
      NODE_ENV: 'production',
      IDENTITY_JWT_PRIVATE_KEY: encodedPem,
    });
    const [jwk] = service.jwks().keys;

    for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(jwk).not.toHaveProperty(secret);
    }
    expect(jwk).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    expect(jwk.kid).toBeTruthy();
  });

  it('mints a token the JWKS verifies, carrying the subject and method', async () => {
    const clock = new FakeClock();
    const service = await bootedService(
      { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
      clock
    );

    const { token, expiresAt, expiresIn } = await service.sign({
      subject: 'subject-id',
      method: 'wallet',
    });
    const { payload } = await jose.jwtVerify(token, await verificationKeyFrom(service), {
      issuer: IDENTITY_TOKEN_ISSUER,
      audience: IDENTITY_TOKEN_AUDIENCE,
      currentDate: clock.now(),
    });

    expect(payload.sub).toBe('subject-id');
    expect(payload.method).toBe('wallet');
    expect(expiresAt.getTime()).toBe(clock.now().getTime() + 300_000);
    expect(expiresIn).toBe(300);
  });

  it('refuses a token signed by anything other than the configured key', async () => {
    const service = await bootedService({
      NODE_ENV: 'production',
      IDENTITY_JWT_PRIVATE_KEY: encodedPem,
    });
    const impostor = await bootedService({
      NODE_ENV: 'production',
      IDENTITY_JWT_PRIVATE_KEY: encodedIdentitySigningKey(),
    });

    const { token } = await impostor.sign({ subject: 'subject-id', method: 'google' });

    await expect(jose.jwtVerify(token, await verificationKeyFrom(service))).rejects.toThrow(
      jose.errors.JWSSignatureVerificationFailed
    );
  });

  it('verifies its own token on the injected clock, and refuses it once expired', async () => {
    const clock = new FakeClock();
    const service = await bootedService(
      { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
      clock
    );
    const { token } = await service.sign({ subject: 'subject-id', method: 'google' });

    await expect(service.verify(token)).resolves.toMatchObject({
      subject: 'subject-id',
      method: 'google',
      expiresAt: new Date(clock.now().getTime() + 300_000),
    });

    clock.advanceMs(300_001);
    await expect(service.verify(token)).rejects.toThrow(jose.errors.JWTExpired);
  });

  it('gives every minted token its own token id', async () => {
    const service = await bootedService({ NODE_ENV: 'test' });
    const claims = { subject: 'subject-id', method: 'google' } as const;

    const first = await service.verify((await service.sign(claims)).token);
    const second = await service.verify((await service.sign(claims)).token);

    expect(first.tokenId).not.toBe(second.tokenId);
  });

  it.each([
    {
      name: 'that carries no token id, since no spend could record it',
      jti: undefined,
      refusal: jose.errors.JWTClaimValidationFailed,
    },
    {
      name: 'whose token id is not a UUID, before any spend reads it',
      jti: 'not-a-uuid',
      refusal: /token id/,
    },
  ])('refuses a token $name', async ({ jti, refusal }) => {
    const clock = new FakeClock();
    const service = await bootedService(
      { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
      clock
    );

    const token = await identityTokenWithJti(encodedPem, clock, jti);
    await expect(service.verify(token)).rejects.toThrow(refusal);
  });

  it('refuses a token that carries no expiry', async () => {
    const clock = new FakeClock();
    const service = await bootedService(
      { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
      clock
    );

    const unbounded = await identityTokenWithJti(encodedPem, clock, randomUUID(), 'omitted');
    await expect(service.verify(unbounded)).rejects.toThrow(jose.errors.JWTClaimValidationFailed);
  });

  it('accepts a hand-signed token whose expiry is an ordinary instant', async () => {
    const clock = new FakeClock();
    const service = await bootedService(
      { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
      clock
    );
    const exp = Math.floor(clock.now().getTime() / 1000) + 300;

    const verified = await service.verify(await identityTokenWithRawExp(encodedPem, String(exp)));
    expect(verified.expiresAt).toEqual(new Date(exp * 1000));
  });

  it.each(['1e999', '1e300', String(Date.UTC(200_000, 0, 1) / 1000)])(
    'refuses a token whose expiry %s is no valid instant or is past the token lifetime',
    async (exp) => {
      const service = await bootedService({
        NODE_ENV: 'production',
        IDENTITY_JWT_PRIVATE_KEY: encodedPem,
      });

      await expect(service.verify(await identityTokenWithRawExp(encodedPem, exp))).rejects.toThrow(
        'valid expiry'
      );
    }
  );

  it.each([
    { name: 'at the edge of the skew allowance', past: 360, accepted: true },
    { name: 'one second past the skew allowance', past: 361, accepted: false },
  ])('bounds the expiry $name', async ({ past, accepted }) => {
    const clock = new FakeClock();
    const service = await bootedService(
      { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
      clock
    );
    const exp = String(Math.floor(clock.now().getTime() / 1000) + past);

    const verified = service.verify(await identityTokenWithRawExp(encodedPem, exp));
    if (accepted) {
      await expect(verified).resolves.toBeDefined();
    } else {
      await expect(verified).rejects.toThrow('valid expiry');
    }
  });

  it('refuses a token whose expiry is past, even when it is not finite', async () => {
    const service = await bootedService({
      NODE_ENV: 'production',
      IDENTITY_JWT_PRIVATE_KEY: encodedPem,
    });

    await expect(
      service.verify(await identityTokenWithRawExp(encodedPem, '-1e999'))
    ).rejects.toThrow(jose.errors.JWTExpired);
  });

  it('expires the token on the injected clock, not the wall clock', async () => {
    const clock = new FakeClock();
    const service = await bootedService(
      { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
      clock
    );
    const { token } = await service.sign({ subject: 'subject-id', method: 'email' });
    const key = await verificationKeyFrom(service);

    clock.advanceMs(300_001);
    await expect(jose.jwtVerify(token, key, { currentDate: clock.now() })).rejects.toThrow(
      jose.errors.JWTExpired
    );
  });
});
