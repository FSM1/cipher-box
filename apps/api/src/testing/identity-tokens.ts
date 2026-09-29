import * as jose from 'jose';
import { generateKeyPairSync } from 'node:crypto';
import {
  IDENTITY_TOKEN_AUDIENCE,
  IDENTITY_TOKEN_ISSUER,
} from '../auth/services/identity-token.service';
import { FakeClock } from './fakes';

/** A base64-encoded PKCS8 PEM, exactly as `IDENTITY_JWT_PRIVATE_KEY` carries it. */
export function encodedIdentitySigningKey(): string {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return Buffer.from(privateKey).toString('base64');
}

/**
 * An identity token under the configured key whose `jti` the caller picks, or
 * omits: the shapes the API's own mint never produces.
 */
export async function identityTokenWithJti(
  encodedPem: string,
  clock: FakeClock,
  jti: string | undefined
): Promise<string> {
  const privateKey = Buffer.from(encodedPem, 'base64').toString('utf8');
  const issuedAt = Math.floor(clock.now().getTime() / 1000);
  const builder = new jose.SignJWT({ method: 'google' })
    .setProtectedHeader({ alg: 'RS256', kid: 'cipherbox-identity-1' })
    .setSubject('subject-id')
    .setIssuer(IDENTITY_TOKEN_ISSUER)
    .setAudience(IDENTITY_TOKEN_AUDIENCE)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + 300);
  if (jti !== undefined) builder.setJti(jti);
  return builder.sign(await jose.importPKCS8(privateKey, 'RS256'));
}
