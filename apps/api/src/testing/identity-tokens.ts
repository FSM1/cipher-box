import * as jose from 'jose';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  IDENTITY_TOKEN_AUDIENCE,
  IDENTITY_TOKEN_ISSUER,
  IDENTITY_TOKEN_KID,
  IdentityTokenService,
} from '../auth/services/identity-token.service';
import { FakeClock, fakeConfig, FakeEntropy } from './fakes';

/** The protected header the API's own mint stamps. */
const HEADER = { alg: 'RS256', kid: IDENTITY_TOKEN_KID };

function identitySigningKey(encodedPem: string) {
  return jose.importPKCS8(Buffer.from(encodedPem, 'base64').toString('utf8'), 'RS256');
}

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
  const issuedAt = Math.floor(clock.now().getTime() / 1000);
  const builder = new jose.SignJWT({ method: 'google' })
    .setProtectedHeader(HEADER)
    .setSubject('subject-id')
    .setIssuer(IDENTITY_TOKEN_ISSUER)
    .setAudience(IDENTITY_TOKEN_AUDIENCE)
    .setIssuedAt(issuedAt);
  if (expiry === 'stamped') builder.setExpirationTime(issuedAt + 300);
  if (jti !== undefined) builder.setJti(jti);
  return builder.sign(await identitySigningKey(encodedPem));
}

/**
 * An identity token under the configured key whose `exp` is the raw JSON number
 * `expJson`, such as `1e999`. Signed as raw bytes, since `SignJWT` refuses such values.
 */
export async function identityTokenWithRawExp(
  encodedPem: string,
  expJson: string
): Promise<string> {
  const claims = JSON.stringify({
    iss: IDENTITY_TOKEN_ISSUER,
    aud: IDENTITY_TOKEN_AUDIENCE,
    sub: 'subject-id',
    method: 'google',
    jti: randomUUID(),
  });
  const payload = Buffer.from(`${claims.slice(0, -1)},"exp":${expJson}}`);
  return new jose.CompactSign(payload)
    .setProtectedHeader(HEADER)
    .sign(await identitySigningKey(encodedPem));
}
