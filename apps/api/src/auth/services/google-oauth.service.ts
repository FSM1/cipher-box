import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import * as jose from 'jose';

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

interface GoogleTokenPayload {
  email: string;
  sub: string;
  name?: string;
  email_verified?: boolean;
}

@Injectable()
export class GoogleOAuthService {
  private readonly logger = new Logger(GoogleOAuthService.name);
  private jwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

  private getJwks(): ReturnType<typeof jose.createRemoteJWKSet> {
    if (!this.jwks) {
      this.jwks = jose.createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
    }
    return this.jwks;
  }

  /**
   * Verify a Google OAuth ID token and extract identity claims.
   *
   * @throws UnauthorizedException if token is invalid or missing required claims
   */
  async verifyGoogleToken(idToken: string): Promise<{ email: string; sub: string; name?: string }> {
    const jwks = this.getJwks();

    let payload: GoogleTokenPayload;
    try {
      const result = await jose.jwtVerify(idToken, jwks, {
        algorithms: ['RS256'],
      });
      payload = result.payload as unknown as GoogleTokenPayload;
    } catch (error) {
      this.logger.warn(
        `Google token verification failed: ${error instanceof Error ? error.message : 'unknown error'}`
      );
      throw new UnauthorizedException(
        `Invalid Google token: ${error instanceof Error ? error.message : 'verification failed'}`
      );
    }

    if (!payload.email) {
      throw new UnauthorizedException('Google token missing email claim');
    }

    if (!payload.sub) {
      throw new UnauthorizedException('Google token missing sub claim');
    }

    return {
      email: payload.email,
      sub: payload.sub,
      name: payload.name,
    };
  }
}
