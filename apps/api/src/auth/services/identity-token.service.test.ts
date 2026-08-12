import * as jose from 'jose';
import { generateKeyPairSync } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import {
  IDENTITY_TOKEN_AUDIENCE,
  IDENTITY_TOKEN_ISSUER,
  IdentityTokenService,
} from './identity-token.service';

/** A base64-encoded PKCS8 PEM, exactly as the env var carries it. */
function encodedSigningKey(): string {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return Buffer.from(privateKey).toString('base64');
}

async function bootedService(values: Record<string, string | undefined>, clock = new FakeClock()) {
  const service = new IdentityTokenService(fakeConfig(values).service, clock);
  await service.onModuleInit();
  return service;
}

/** The verification key a Web3Auth custom verifier would build from the JWKS. */
async function verificationKeyFrom(service: IdentityTokenService) {
  const [jwk] = service.jwks().keys;
  return jose.importJWK(jwk, 'RS256');
}

describe('IdentityTokenService', () => {
  let encodedPem: string;

  beforeEach(() => {
    encodedPem = encodedSigningKey();
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

    const { token, expiresAt } = await service.sign({ subject: 'subject-id', method: 'wallet' });
    const { payload } = await jose.jwtVerify(token, await verificationKeyFrom(service), {
      issuer: IDENTITY_TOKEN_ISSUER,
      audience: IDENTITY_TOKEN_AUDIENCE,
      currentDate: clock.now(),
    });

    expect(payload.sub).toBe('subject-id');
    expect(payload.method).toBe('wallet');
    expect(expiresAt.getTime()).toBe(clock.now().getTime() + 300_000);
  });

  it('refuses a token signed by anything other than the configured key', async () => {
    const service = await bootedService({
      NODE_ENV: 'production',
      IDENTITY_JWT_PRIVATE_KEY: encodedPem,
    });
    const impostor = await bootedService({
      NODE_ENV: 'production',
      IDENTITY_JWT_PRIVATE_KEY: encodedSigningKey(),
    });

    const { token } = await impostor.sign({ subject: 'subject-id', method: 'google' });

    await expect(jose.jwtVerify(token, await verificationKeyFrom(service))).rejects.toThrow(
      jose.errors.JWSSignatureVerificationFailed
    );
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
