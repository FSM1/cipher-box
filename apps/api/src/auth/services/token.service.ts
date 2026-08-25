import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, LessThan, Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { Entropy } from '../../common/entropy';
import { sha256Hex } from '../../common/hash';
import type { TokenScope } from '../decorators/allow-scope.decorator';
import { RefreshToken } from '../entities/refresh-token.entity';
import { GatewayTokenService } from './gateway-token.service';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  /** The read accelerator's opaque pseudonym, minted by GatewayTokenService. */
  gatewayToken: string;
}

export interface ScopedToken {
  accessToken: string;
  expiresIn: number;
}

/**
 * Long enough for a rendezvous to run and the device to reconstruct behind it,
 * short enough that a leak is stale; via SCOPED_TOKEN_TTL_SECONDS.
 */
const DEFAULT_SCOPED_TTL_SECONDS = 600;

/**
 * Ceiling on the configured scoped TTL. The token is non-refreshable precisely
 * so a leak expires, so a misconfigured value must fail closed to the default
 * rather than turn the capability into a long-lived bearer credential.
 */
const MAX_SCOPED_TTL_SECONDS = 3600;

/**
 * Short-lived access JWT + rotating refresh token (blueprint/api.md,
 * Identity and auth).
 *
 * Refresh tokens are one-time-use members of a family: every refresh marks
 * the presented token used and issues a successor in the same family.
 * Presenting an already-used token is reuse detection — the whole family is
 * hard-deleted (every descendant dies with it), forcing a fresh login.
 * Logout and revocation are hard deletes, never soft flags.
 *
 * A third credential rides the same rotation: the read accelerator's opaque
 * pseudonym, minted per family so it dies with the session that owns it.
 */
@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly refreshTtlMs: number;
  private readonly scopedTtlSeconds: number;

  constructor(
    private readonly jwtService: JwtService,
    private readonly clock: Clock,
    private readonly entropy: Entropy,
    private readonly gatewayTokenService: GatewayTokenService,
    configService: ConfigService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>
  ) {
    const days = Number(configService.get('REFRESH_TOKEN_TTL_DAYS') ?? 7);
    this.refreshTtlMs = days * 24 * 60 * 60 * 1000;
    this.scopedTtlSeconds = positiveIntConfig(
      configService.get('SCOPED_TOKEN_TTL_SECONDS'),
      DEFAULT_SCOPED_TTL_SECONDS,
      MAX_SCOPED_TTL_SECONDS
    );
  }

  /** Issue an access JWT and start a fresh refresh-token family. */
  async createTokenPair(userId: string, publicKey: string): Promise<TokenPair> {
    const accessToken = await this.signAccessToken(userId, publicKey);
    const session = await this.mintSessionCredentials(userId, this.entropy.randomUuid());
    return { accessToken, ...session };
  }

  /**
   * A capability, not a session: the token carries a `scope` claim the guard
   * reads, and no refresh-token family is started — so a device that cannot yet
   * reconstruct its key reaches the routes naming that scope and nothing else,
   * and cannot extend its own reach past one short TTL.
   *
   * It deliberately omits the account `publicKey` a full session carries. Its
   * holder has proven control of an identity provider, not of the vault key the
   * publicKey is derived from, and that key is the account's network-wide
   * pseudonym — handing it over would link the two for a party that cannot
   * otherwise connect them.
   */
  async createScopedToken(userId: string, scope: TokenScope): Promise<ScopedToken> {
    const accessToken = await this.jwtService.signAsync(
      { sub: userId, scope },
      { expiresIn: this.scopedTtlSeconds }
    );
    return { accessToken, expiresIn: this.scopedTtlSeconds };
  }

  /**
   * Rotate a refresh token: single-use, successor in the same family,
   * family-wide hard delete on reuse detection.
   */
  async rotate(
    rawToken: string,
    publicKeyByUserId: (userId: string) => Promise<string>
  ): Promise<TokenPair> {
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

    // Opportunistic housekeeping: expired rows are dead fuel — a replayed
    // expired token dies in the expiry check regardless of reuse state — so
    // rotation sweeps them out instead of letting them accumulate forever.
    await this.refreshTokenRepository.delete({
      userId: existing.userId,
      expiresAt: LessThan(now),
    });

    const publicKey = await publicKeyByUserId(existing.userId);
    const accessToken = await this.signAccessToken(existing.userId, publicKey);
    const session = await this.mintSessionCredentials(existing.userId, existing.familyId);
    return { accessToken, ...session };
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

  /**
   * A family's two stored credentials, born together: the refresh row that
   * defines the session, and the pseudonym whose validity derives from it.
   */
  private async mintSessionCredentials(
    userId: string,
    familyId: string
  ): Promise<{ refreshToken: string; gatewayToken: string }> {
    const rawToken = this.entropy.randomBytes(32).toString('hex');
    await this.refreshTokenRepository.save({
      userId,
      familyId,
      tokenHash: this.hashToken(rawToken),
      expiresAt: new Date(this.clock.now().getTime() + this.refreshTtlMs),
      usedAt: null,
    });
    return {
      refreshToken: rawToken,
      gatewayToken: await this.gatewayTokenService.mintForFamily(userId, familyId),
    };
  }

  private hashToken(rawToken: string): string {
    return sha256Hex(rawToken);
  }
}
