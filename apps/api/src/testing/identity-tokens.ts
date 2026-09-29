import * as jose from 'jose';
import { createSign, generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  IDENTITY_TOKEN_AUDIENCE,
  IDENTITY_TOKEN_ISSUER,
  IdentityTokenService,
} from '../auth/services/identity-token.service';
import { FakeClock, fakeConfig, FakeEntropy } from './fakes';

/** A base64-encoded PKCS8 PEM, exactly as `IDENTITY_JWT_PRIVATE_KEY` carries it. */
export function encodedIdentitySigningKey(): string {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return Buffer.from(privateKey).toString('base64');
}

/** A real token service, booted on `values` as the module boots it. */
export async function bootedIdentityTokenService(
  values: Record<string, string | undefined>,
  clock = new FakeClock()
): Promise<IdentityTokenService> {
  const service = new IdentityTokenService(fakeConfig(values).service, clock, new FakeEntropy());
  await service.onModuleInit();
  return service;
}

/**
 * An identity token under the configured key whose `jti` the caller picks, or
 * omits, and whose expiry the caller may omit: the shapes the API's own mint
 * never produces.
 */
export async function identityTokenWithJti(
  encodedPem: string,
  clock: FakeClock,
  jti: string | undefined,
  expiry: 'stamped' | 'omitted' = 'stamped'
): Promise<string> {
  const privateKey = Buffer.from(encodedPem, 'base64').toString('utf8');
  const issuedAt = Math.floor(clock.now().getTime() / 1000);
  const builder = new jose.SignJWT({ method: 'google' })
    .setProtectedHeader({ alg: 'RS256', kid: 'cipherbox-identity-1' })
    .setSubject('subject-id')
    .setIssuer(IDENTITY_TOKEN_ISSUER)
    .setAudience(IDENTITY_TOKEN_AUDIENCE)
    .setIssuedAt(issuedAt);
  if (expiry === 'stamped') builder.setExpirationTime(issuedAt + 300);
  if (jti !== undefined) builder.setJti(jti);
  return builder.sign(await jose.importPKCS8(privateKey, 'RS256'));
}

/**
 * An identity token under the configured key whose `exp` is the raw JSON number
 * `expJson`, such as `1e999`. Signed by hand, since `SignJWT` refuses such values.
 */
export function identityTokenWithRawExp(encodedPem: string, expJson: string): string {
  const privateKey = Buffer.from(encodedPem, 'base64').toString('utf8');
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'cipherbox-identity-1' }));
  const claims = JSON.stringify({
    iss: IDENTITY_TOKEN_ISSUER,
    aud: IDENTITY_TOKEN_AUDIENCE,
    sub: 'subject-id',
    method: 'google',
    jti: randomUUID(),
  });
  const payload = Buffer.from(`${claims.slice(0, -1)},"exp":${expJson}}`);
  const signingInput = `${header.toString('base64url')}.${payload.toString('base64url')}`;
  const signature = createSign('RSA-SHA256').update(signingInput).sign(privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}
