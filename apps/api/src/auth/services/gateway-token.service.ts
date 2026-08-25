import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'node:crypto';
import { Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { Entropy } from '../../common/entropy';
import { GatewayToken } from '../entities/gateway-token.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { resolveAccessTtlSeconds } from './access-ttl';

/** 32 random bytes, lowercase hex — the shape `verify` accepts. */
export const GATEWAY_TOKEN_PATTERN = /^[0-9a-f]{64}$/;

/**
 * How long a verified token stays trusted in process. This is the revocation
 * latency: a token whose session died is still honoured until its entry ages
 * out, so the window is seconds, not minutes.
 */
const DEFAULT_CACHE_TTL_SECONDS = 10;
const MAX_CACHE_TTL_SECONDS = 60;

/** Bound on cached entries, so the verify path cannot grow memory without end. */
const DEFAULT_CACHE_MAX_ENTRIES = 10_000;

/**
 * The read accelerator's credential: an opaque per-session pseudonym minted
 * beside the access token and verified by lookup (blueprint/api.md, Egress).
 *
 * The gateway front is the only caller of `verify`, at roughly one request per
 * leaf block, so the lookup sits behind a small in-process cache. Nothing about
 * the account crosses back — the answer is yes or no.
 */
@Injectable()
export class GatewayTokenService {
  private readonly ttlSeconds: number;
  private readonly cacheTtlMs: number;
  private readonly cacheMaxEntries: number;
  /** tokenHash → epoch ms the entry stops being trusted. Insertion-ordered. */
  private readonly cache = new Map<string, number>();

  constructor(
    private readonly clock: Clock,
    private readonly entropy: Entropy,
    configService: ConfigService,
    @InjectRepository(GatewayToken)
    private readonly gatewayTokenRepository: Repository<GatewayToken>
  ) {
    this.ttlSeconds = resolveAccessTtlSeconds(configService);
    this.cacheTtlMs =
      positiveIntConfig(
        configService.get('GATEWAY_TOKEN_CACHE_TTL_SECONDS'),
        DEFAULT_CACHE_TTL_SECONDS,
        MAX_CACHE_TTL_SECONDS
      ) * 1000;
    this.cacheMaxEntries = positiveIntConfig(
      configService.get('GATEWAY_TOKEN_CACHE_MAX_ENTRIES'),
      DEFAULT_CACHE_MAX_ENTRIES
    );
  }

  /**
   * Mint this session's pseudonym, then drop the family's previous one and any
   * of the account's expired rows in one statement. Insert first: a failed
   * sweep leaves a second live token that expires on its own, where a failed
   * insert after a sweep would leave the session with no accelerator at all.
   */
  async mintForFamily(userId: string, familyId: string): Promise<string> {
    const rawToken = this.entropy.randomBytes(32).toString('hex');
    const now = this.clock.now();
    const minted = await this.gatewayTokenRepository.save({
      userId,
      familyId,
      tokenHash: this.hashToken(rawToken),
      expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
    });
    await this.gatewayTokenRepository
      .createQueryBuilder()
      .delete()
      .where('user_id = :userId', { userId })
      .andWhere('id != :minted', { minted: minted.id })
      .andWhere('(family_id = :familyId OR expires_at <= :now)', { familyId, now })
      .execute();
    return rawToken;
  }

  /**
   * Whether the presented token still names a live session. Fails closed on
   * anything that is not the minted shape, before the row is looked up.
   */
  async verify(rawToken: string): Promise<boolean> {
    if (!GATEWAY_TOKEN_PATTERN.test(rawToken)) {
      return false;
    }
    const tokenHash = this.hashToken(rawToken);
    const now = this.clock.now();
    const trustedUntil = this.cache.get(tokenHash);
    if (trustedUntil !== undefined) {
      if (trustedUntil > now.getTime()) {
        return true;
      }
      this.cache.delete(tokenHash);
    }

    const live = await this.gatewayTokenRepository
      .createQueryBuilder('gateway')
      .select('gateway.expiresAt', 'expires_at')
      // A pseudonym is only as alive as the session that minted it: the family
      // must still hold an unused, unexpired refresh row. Logout, reuse
      // detection, and the account cascade all delete those rows, so each
      // revokes gateway reads without a second path to keep in step.
      .innerJoin(
        RefreshToken,
        'refresh',
        'refresh.family_id = gateway.family_id AND refresh.used_at IS NULL AND refresh.expires_at > :now'
      )
      .where('gateway.token_hash = :tokenHash', { tokenHash })
      .andWhere('gateway.expires_at > :now')
      .setParameter('now', now)
      .getRawOne<{ expires_at: Date }>();
    if (!live) {
      return false;
    }

    this.remember(tokenHash, Math.min(live.expires_at.getTime(), now.getTime() + this.cacheTtlMs));
    return true;
  }

  /** Cached-answer lifetime in ms — the bound on how stale a `verify` can be. */
  get revocationLatencyMs(): number {
    return this.cacheTtlMs;
  }

  private remember(tokenHash: string, trustedUntil: number): void {
    if (trustedUntil <= this.clock.now().getTime()) {
      return;
    }
    // Re-insert so Map iteration order stays oldest-first for the eviction below.
    this.cache.delete(tokenHash);
    this.cache.set(tokenHash, trustedUntil);
    while (this.cache.size > this.cacheMaxEntries) {
      const oldest = this.cache.keys().next();
      if (oldest.done) {
        return;
      }
      this.cache.delete(oldest.value);
    }
  }

  private hashToken(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
  }
}
