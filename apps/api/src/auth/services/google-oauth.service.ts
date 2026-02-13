import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUER = 'https://accounts.google.com';

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
  private readonly googleClientId: string;

  constructor(private config: ConfigService) {
    this.googleClientId = this.config.get<string>('GOOGLE_CLIENT_ID', '');
    if (!this.googleClientId && this.config.get<string>('NODE_ENV') === 'production') {
      throw new Error('GOOGLE_CLIENT_ID must be set in production');
    }
    if (!this.googleClientId) {
      this.logger.warn('GOOGLE_CLIENT_ID not set — audience validation disabled (dev/staging only)');
    }
  }

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
      const verifyOptions: jose.JWTVerifyOptions = {
        algorithms: ['RS256'],
        issuer: GOOGLE_ISSUER,
      };
      if (this.googleClientId) {
        verifyOptions.audience = this.googleClientId;
      }
      const result = await jose.jwtVerify(idToken, jwks, verifyOptions);
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

    if (payload.email_verified === false) {
      throw new UnauthorizedException('Google email address is not verified');
    }

    return {
      email: payload.email,
      sub: payload.sub,
      name: payload.name,
    };
  }
}
