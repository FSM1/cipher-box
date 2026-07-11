import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import { RefreshToken } from '../entities/refresh-token.entity';

interface TokenPair {
  accessToken: string;
  /** Empty string when skipRefreshToken is set (falsy, safe for conditional checks) */
  refreshToken: string;
}

interface CreateTokenOptions {
  /** Restrict token to specific API scopes (e.g., ['device-approval']) */
  scope?: string[];
  /** Skip refresh token generation (for temp auth flows) */
  skipRefreshToken?: boolean;
}

@Injectable()
export class TokenService {
  private readonly REFRESH_TOKEN_EXPIRY_DAYS = 7;

  /**
   * Access-token lifetime. Defaults to the production-safe 15 minutes, but is
   * overridable via ACCESS_TOKEN_TTL for long-running headless E2E sessions
   * (the desktop test-login binary holds a single token for the whole suite
   * and cannot silently refresh, so a short TTL expires mid-run).
   */
  private readonly ACCESS_TOKEN_TTL: JwtSignOptions['expiresIn'] =
    (process.env.ACCESS_TOKEN_TTL as JwtSignOptions['expiresIn']) || '15m';

  constructor(
    private jwtService: JwtService,
    @InjectRepository(RefreshToken)
    private refreshTokenRepo: Repository<RefreshToken>
  ) {}

  async createTokens(
    userId: string,
    publicKey: string,
    options?: CreateTokenOptions
  ): Promise<TokenPair> {
    // Generate access token (include scope claim if restricted)
    const payload: Record<string, unknown> = { sub: userId, publicKey };
    if (options?.scope) {
      payload.scope = options.scope;
    }
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.ACCESS_TOKEN_TTL,
    });

    // Skip refresh token for temp auth (scoped tokens should not be refreshable)
    if (options?.skipRefreshToken) {
      return { accessToken, refreshToken: '' };
    }

    // Generate refresh token
    const refreshToken = randomBytes(32).toString('hex');
    const tokenHash = await argon2.hash(refreshToken);

    // Calculate expiry date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_EXPIRY_DAYS);

    // Save to database with prefix for O(1) lookup
    const tokenPrefix = refreshToken.substring(0, 16);
    await this.refreshTokenRepo.save({
      userId,
      tokenHash,
      tokenPrefix,
      expiresAt,
    });

    return { accessToken, refreshToken };
  }

  async rotateRefreshToken(
    oldRefreshToken: string,
    userId: string,
    publicKey: string
  ): Promise<TokenPair> {
    // Find candidate tokens by prefix for O(1) lookup instead of O(N) Argon2 scan
    const prefix = oldRefreshToken.substring(0, 16);
    const tokens = await this.refreshTokenRepo.find({
      where: {
        userId,
        tokenPrefix: prefix,
        revokedAt: IsNull(),
      },
    });

    // Find matching token
    let validToken: RefreshToken | null = null;
    for (const token of tokens) {
      try {
        if (await argon2.verify(token.tokenHash, oldRefreshToken)) {
          validToken = token;
          break;
        }
      } catch {
        // argon2.verify throws on invalid hash format, continue checking
        continue;
      }
    }

    if (!validToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (validToken.expiresAt < new Date()) {
      // Revoke expired token
      validToken.revokedAt = new Date();
      await this.refreshTokenRepo.save(validToken);
      throw new UnauthorizedException('Refresh token expired');
    }

    // Revoke old token
    validToken.revokedAt = new Date();
    await this.refreshTokenRepo.save(validToken);

    // Create new tokens
    return this.createTokens(userId, publicKey);
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.refreshTokenRepo.update({ userId, revokedAt: IsNull() }, { revokedAt: new Date() });
  }

  async revokeToken(tokenId: string): Promise<void> {
    await this.refreshTokenRepo.update(
      { id: tokenId, revokedAt: IsNull() },
      { revokedAt: new Date() }
    );
  }
}
