import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import { RefreshToken } from '../entities/refresh-token.entity';

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class TokenService {
  private readonly REFRESH_TOKEN_EXPIRY_DAYS = 7;

  constructor(
    private jwtService: JwtService,
    @InjectRepository(RefreshToken)
    private refreshTokenRepo: Repository<RefreshToken>
  ) {}

  async createTokens(userId: string, publicKey: string): Promise<TokenPair> {
    // Generate access token
    const accessToken = this.jwtService.sign({ sub: userId, publicKey }, { expiresIn: '15m' });

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
