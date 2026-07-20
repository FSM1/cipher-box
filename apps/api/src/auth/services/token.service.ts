import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'node:crypto';
import { IsNull, Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { Entropy } from '../../common/entropy';
import { RefreshToken } from '../entities/refresh-token.entity';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

/**
 * Short-lived access JWT + rotating refresh token (blueprint/api.md,
 * Identity and auth).
 *
 * Refresh tokens are one-time-use members of a family: every refresh marks
 * the presented token used and issues a successor in the same family.
 * Presenting an already-used token is reuse detection — the whole family is
 * hard-deleted (every descendant dies with it), forcing a fresh login.
 * Logout and revocation are hard deletes, never soft flags.
 */
@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly refreshTtlMs: number;

  constructor(
    private readonly jwtService: JwtService,
    private readonly clock: Clock,
    private readonly entropy: Entropy,
    configService: ConfigService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>
  ) {
    const days = Number(configService.get('REFRESH_TOKEN_TTL_DAYS') ?? 7);
    this.refreshTtlMs = days * 24 * 60 * 60 * 1000;
  }

  /** Issue an access JWT and start a fresh refresh-token family. */
  async createTokenPair(userId: string, publicKey: string): Promise<TokenPair> {
    const accessToken = await this.signAccessToken(userId, publicKey);
    const refreshToken = await this.mintRefreshToken(userId, this.entropy.randomUuid());
    return { accessToken, refreshToken };
  }

  /**
   * Rotate a refresh token: single-use, successor in the same family,
   * family-wide hard delete on reuse detection.
   */
  async rotate(rawToken: string, publicKeyByUserId: (userId: string) => Promise<string>) {
    const now = this.clock.now();
    const tokenHash = this.hashToken(rawToken);
    const existing = await this.refreshTokenRepository.findOne({ where: { tokenHash } });

    if (!existing) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (existing.usedAt !== null) {
      // Reuse detected: the token was already rotated once. Someone —
      // legitimate client or thief — is replaying. Kill the whole family.
      await this.refreshTokenRepository.delete({ familyId: existing.familyId });
      this.logger.warn(
        `Refresh token reuse detected; family revoked (userId=${existing.userId}, familyId=${existing.familyId})`
      );
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (existing.expiresAt.getTime() <= now.getTime()) {
      await this.refreshTokenRepository.delete({ familyId: existing.familyId });
      throw new UnauthorizedException('Refresh token expired');
    }

    // Atomic single-use claim: only one concurrent rotation can win.
    const claim = await this.refreshTokenRepository.update(
      { id: existing.id, usedAt: IsNull() },
      { usedAt: now }
    );
    if (!claim.affected) {
      await this.refreshTokenRepository.delete({ familyId: existing.familyId });
      throw new UnauthorizedException('Invalid refresh token');
    }

    const publicKey = await publicKeyByUserId(existing.userId);
    const accessToken = await this.signAccessToken(existing.userId, publicKey);
    const refreshToken = await this.mintRefreshToken(existing.userId, existing.familyId);
    return { pair: { accessToken, refreshToken }, userId: existing.userId };
  }

  /** Hard-delete every refresh token the user holds (logout everywhere). */
  async revokeAllForUser(userId: string): Promise<void> {
    await this.refreshTokenRepository.delete({ userId });
  }

  get refreshTokenTtlMs(): number {
    return this.refreshTtlMs;
  }

  private async signAccessToken(userId: string, publicKey: string): Promise<string> {
    return this.jwtService.signAsync({ sub: userId, publicKey });
  }

  private async mintRefreshToken(userId: string, familyId: string): Promise<string> {
    const rawToken = this.entropy.randomBytes(32).toString('hex');
    await this.refreshTokenRepository.save({
      userId,
      familyId,
      tokenHash: this.hashToken(rawToken),
      expiresAt: new Date(this.clock.now().getTime() + this.refreshTtlMs),
      usedAt: null,
    });
    return rawToken;
  }

  private hashToken(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
  }
}
