import { UnauthorizedException } from '@nestjs/common';
import * as jose from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { fakeConfig } from '../../testing/fakes';
import { GoogleOAuthService } from './google-oauth.service';

const CLIENT_ID = 'cipherbox.apps.googleusercontent.com';
const GOOGLE_ISSUER = 'https://accounts.google.com';

let googleKey: jose.CryptoKey;
let impostorKey: jose.CryptoKey;
/** Stands in for Google's published certs. */
let googleKeys: jose.JWTVerifyGetKey;

/** A token shaped exactly like a Google ID token, signed by `key`. */
function idToken(
  claims: jose.JWTPayload,
  key: jose.CryptoKey,
  overrides: { issuer?: string; audience?: string } = {}
): Promise<string> {
  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(overrides.issuer ?? GOOGLE_ISSUER)
    .setAudience(overrides.audience ?? CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key);
}

function service(values: Record<string, string | undefined> = {}) {
  return new GoogleOAuthService(
    fakeConfig({ NODE_ENV: 'test', GOOGLE_CLIENT_ID: CLIENT_ID, ...values }).service,
    googleKeys
  );
}

beforeAll(async () => {
  const google = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
  const impostor = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
  googleKey = google.privateKey;
  impostorKey = impostor.privateKey;
  googleKeys = () => Promise.resolve(google.publicKey);
});

describe('GoogleOAuthService', () => {
  it('refuses to boot without a client ID in any deployed environment', () => {
    expect(() => new GoogleOAuthService(fakeConfig({ NODE_ENV: 'production' }).service)).toThrow(
      /GOOGLE_CLIENT_ID is required/
    );
    expect(() => new GoogleOAuthService(fakeConfig({ NODE_ENV: 'staging' }).service)).toThrow(
      /GOOGLE_CLIENT_ID is required/
    );
  });

  it('accepts a Google-signed token and reads the immutable subject', async () => {
    const token = await idToken({ sub: 'google-subject', email: 'member@example.com' }, googleKey);

    await expect(service().verify(token)).resolves.toEqual({
      subject: 'google-subject',
      email: 'member@example.com',
    });
  });

  it('refuses a token signed by anything other than Google', async () => {
    const token = await idToken(
      { sub: 'google-subject', email: 'member@example.com' },
      impostorKey
    );

    await expect(service().verify(token)).rejects.toThrow(UnauthorizedException);
  });

  it('refuses a token minted for a different OAuth client', async () => {
    const token = await idToken({ sub: 'google-subject', email: 'member@example.com' }, googleKey, {
      audience: 'someone-elses-client-id',
    });

    await expect(service().verify(token)).rejects.toThrow(UnauthorizedException);
  });

  // v1 skipped the audience check when no client ID was configured; here it is
  // always enforced, so an unconfigured profile fails closed rather than open.
  it('still enforces an audience when no client ID is configured', async () => {
    const token = await idToken({ sub: 'google-subject', email: 'member@example.com' }, googleKey);

    await expect(service({ GOOGLE_CLIENT_ID: undefined }).verify(token)).rejects.toThrow(
      UnauthorizedException
    );
  });

  it('refuses a token from an issuer that is not Google', async () => {
    const token = await idToken({ sub: 'google-subject', email: 'member@example.com' }, googleKey, {
      issuer: 'https://accounts.example.com',
    });

    await expect(service().verify(token)).rejects.toThrow(UnauthorizedException);
  });

  it('refuses a token whose email Google has not verified', async () => {
    const token = await idToken(
      { sub: 'google-subject', email: 'member@example.com', email_verified: false },
      googleKey
    );

    await expect(service().verify(token)).rejects.toThrow(UnauthorizedException);
  });

  it('refuses a token missing the claims the exchange is keyed on', async () => {
    const noEmail = await idToken({ sub: 'google-subject' }, googleKey);
    await expect(service().verify(noEmail)).rejects.toThrow(UnauthorizedException);
  });
});
