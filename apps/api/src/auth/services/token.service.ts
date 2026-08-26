import {
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, EntityManager, FindOptionsWhere, IsNull, LessThan, Repository } from 'typeorm';
import {
  boundedAcquire,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  sessionCredentialLockKey,
} from '../../common/advisory-lock';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { Entropy } from '../../common/entropy';
import { sha256Hex } from '../../common/hash';
import type { TokenScope } from '../decorators/allow-scope.decorator';
import { RefreshToken } from '../entities/refresh-token.entity';
import { refreshRowState } from '../refresh-liveness';
import { AcceleratorTokenService } from './accelerator-token.service';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  /** The read accelerator's opaque pseudonym, minted by AcceleratorTokenService. */
  acceleratorToken: string;
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
  private readonly lockTimeoutMs: number;

  constructor(
    private readonly jwtService: JwtService,
    private readonly clock: Clock,
    private readonly entropy: Entropy,
    private readonly acceleratorTokenService: AcceleratorTokenService,
    configService: ConfigService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
    @InjectDataSource()
    private readonly dataSource: DataSource
  ) {
    const days = Number(configService.get('REFRESH_TOKEN_TTL_DAYS') ?? 7);
    this.refreshTtlMs = days * 24 * 60 * 60 * 1000;
    this.scopedTtlSeconds = positiveIntConfig(
      configService.get('SCOPED_TOKEN_TTL_SECONDS'),
      DEFAULT_SCOPED_TTL_SECONDS,
      MAX_SCOPED_TTL_SECONDS
    );
    this.lockTimeoutMs = resolveAdvisoryLockTimeoutMs(configService);
  }

  /** Issue an access JWT and start a fresh refresh-token family. */
  async createTokenPair(userId: string, publicKey: string): Promise<TokenPair> {
    const accessToken = await this.signAccessToken(userId, publicKey);
    const familyId = this.entropy.randomUuid();
    const session = await this.inSessionTransaction(userId, (manager) =>
      this.mintSessionCredentials(userId, familyId, manager)
    );
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
   *
   * The claim and everything issued beside it commit together, so a failure
   * part-way through leaves the presented token unspent and the client's retry
   * succeeds rather than tripping reuse detection. A revocation must commit
   * while the request fails, so revocations stay outside that transaction.
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

    const state = refreshRowState(existing, now);
    if (state === 'spent') {
      // Reuse detected: the token was already rotated once. Someone —
      // legitimate client or thief — is replaying. Logged before the delete so
      // the signal survives however the revocation goes.
      this.logger.warn(
        `Refresh token reuse detected; family revoked (userId=${existing.userId}, familyId=${existing.familyId})`
      );
      await this.revokeFamily(existing.userId, existing.familyId);
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (state === 'expired') {
      await this.revokeFamily(existing.userId, existing.familyId);
      throw new UnauthorizedException('Refresh token expired');
    }

    // Signed before the transaction: nothing that can fail on its own may run
    // once the presented token is spent.
    const publicKey = await publicKeyByUserId(existing.userId);
    const accessToken = await this.signAccessToken(existing.userId, publicKey);

    const session = await this.inSessionTransaction(existing.userId, async (manager) => {
      const rows = manager.getRepository(RefreshToken);
      // Atomic single-use claim: only one concurrent rotation can win. The
      // loser has written nothing, so it revokes once this releases the lock.
      const claim = await rows.update({ id: existing.id, usedAt: IsNull() }, { usedAt: now });
      if (!claim.affected) {
        return null;
      }
      // Expired rows are dead fuel — a replayed expired token dies in the
      // expiry check regardless of reuse state — so rotation sweeps them out
      // instead of letting them accumulate forever.
      await rows.delete({ userId: existing.userId, expiresAt: LessThan(now) });
      return this.mintSessionCredentials(existing.userId, existing.familyId, manager);
    });

    if (!session) {
      await this.revokeFamily(existing.userId, existing.familyId);
      throw new UnauthorizedException('Invalid refresh token');
    }
    return { accessToken, ...session };
  }

  /** Hard-delete every refresh token the user holds (logout everywhere). */
  async revokeAllForUser(userId: string): Promise<void> {
    await this.revoke(userId, { userId });
  }

  get refreshTokenTtlMs(): number {
    return this.refreshTtlMs;
  }

  private async signAccessToken(userId: string, publicKey: string): Promise<string> {
    return this.jwtService.signAsync({ sub: userId, publicKey });
  }

  private async revokeFamily(userId: string, familyId: string): Promise<void> {
    await this.revoke(userId, { familyId });
  }

  /**
   * Hard-delete refresh rows under the same lock rotation takes: a bare DELETE
   * reads the snapshot it opened with, so a successor a concurrent rotation
   * commits after that point would survive the revocation meant to kill it.
   *
   * Contention must never cost a revocation, so a wait past the bound falls
   * back to the unserialized delete rather than abandoning it — that can miss
   * such a successor, but it can never leave the rows it does see alive.
   */
  private async revoke(userId: string, criteria: FindOptionsWhere<RefreshToken>): Promise<void> {
    try {
      await this.inSessionTransaction(userId, (manager) =>
        manager.getRepository(RefreshToken).delete(criteria)
      );
    } catch (error) {
      if (!(error instanceof ServiceUnavailableException)) {
        throw error;
      }
      await this.refreshTokenRepository.delete(criteria);
    }
  }

  /**
   * Serialize an account's session-credential writes on one advisory key. A wait
   * past the bound is the retryable 503, which leaves the presented refresh
   * token unspent — see `sessionCredentialLockKey`.
   */
  private inSessionTransaction<T>(
    userId: string,
    work: (manager: EntityManager) => Promise<T>
  ): Promise<T> {
    return runLockGuardedTransaction(this.dataSource, async (manager) => {
      await boundedAcquire(manager, [sessionCredentialLockKey(userId)], this.lockTimeoutMs);
      return work(manager);
    });
  }

  /**
   * A family's two stored credentials, born together: the refresh row that
   * defines the session, and the pseudonym whose validity derives from it.
   * Both writes ride the caller's transaction so neither can outlive the other.
   */
  private async mintSessionCredentials(
    userId: string,
    familyId: string,
    manager: EntityManager
  ): Promise<{ refreshToken: string; acceleratorToken: string }> {
    const rawToken = this.entropy.randomBytes(32).toString('hex');
    await manager.getRepository(RefreshToken).save({
      userId,
      familyId,
      tokenHash: this.hashToken(rawToken),
      expiresAt: new Date(this.clock.now().getTime() + this.refreshTtlMs),
      usedAt: null,
    });
    return {
      refreshToken: rawToken,
      acceleratorToken: await this.acceleratorTokenService.mintForFamily(userId, familyId, manager),
    };
  }

  private hashToken(rawToken: string): string {
    return sha256Hex(rawToken);
  }
}
