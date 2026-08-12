import { Injectable, Optional, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
/** Google mints both spellings of its own issuer. */
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

/**
 * A value no Google token can ever carry, so an undeployed profile that never
 * configured a client ID still fails the audience check rather than skipping
 * it. Deployed profiles refuse to boot without the real one.
 */
const UNCONFIGURED_AUDIENCE = 'cipherbox-google-client-id-unset';

export interface GoogleIdentity {
  /** Google's immutable subject id — the account handle. The email can change. */
  subject: string;
  email: string;
}

/**
 * Verifies the Google ID token the web app collects (ADR 0008 D1). The client
 * ID here is the OAuth provider's, distinct from the Web3Auth project's.
 */
@Injectable()
export class GoogleOAuthService {
  private readonly audience: string;
  private readonly keys: jose.JWTVerifyGetKey;

  // `keys` is a test seam for a fake JWKS. Nest reads every constructor
  // position from `design:paramtypes`, where an interface type emits no
  // injectable token — `@Optional()` is what makes it inject `undefined`
  // instead of refusing to resolve the provider.
  constructor(configService: ConfigService, @Optional() keys?: jose.JWTVerifyGetKey) {
    const nodeEnv = configService.get<string>('NODE_ENV') ?? 'development';
    const clientId = configService.get<string>('GOOGLE_CLIENT_ID')?.trim();
    if (!clientId && nodeEnv !== 'development' && nodeEnv !== 'test') {
      throw new Error(`GOOGLE_CLIENT_ID is required when NODE_ENV is '${nodeEnv}'`);
    }
    this.audience = clientId || UNCONFIGURED_AUDIENCE;
    this.keys = keys ?? jose.createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
  }

  async verify(idToken: string): Promise<GoogleIdentity> {
    let payload: jose.JWTPayload;
    try {
      ({ payload } = await jose.jwtVerify(idToken, this.keys, {
        algorithms: ['RS256'],
        issuer: GOOGLE_ISSUERS,
        audience: this.audience,
      }));
    } catch {
      // The cause names key ids and audiences; the member can act on none of it.
      throw new UnauthorizedException('Google token verification failed');
    }

    const email = typeof payload.email === 'string' ? payload.email : null;
    if (!payload.sub || !email) {
      throw new UnauthorizedException('Google token is missing its sub or email claim');
    }
    if (payload.email_verified === false) {
      throw new UnauthorizedException('The Google email address is not verified');
    }
    return { subject: payload.sub, email };
  }
}
