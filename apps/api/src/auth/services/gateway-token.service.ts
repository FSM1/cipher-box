import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { Entropy } from '../../common/entropy';
import { sha256Hex } from '../../common/hash';
import { HEX_32_BYTES_RE } from '../../common/patterns';
import { GatewayToken } from '../entities/gateway-token.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { resolveAccessTtlSeconds } from './access-ttl';

/**
 * How long a verified token stays trusted in process — the revocation latency,
 * so it is seconds rather than minutes.
 */
const DEFAULT_CACHE_TTL_SECONDS = 10;
const MAX_CACHE_TTL_SECONDS = 60;

/**
 * Refusals age out far faster than acceptances: their keys are attacker-chosen,
 * so a long life would let a spray of invented tokens hold the cache full and
 * evict live entries. One second still collapses a per-block retry storm into a
 * single lookup.
 */
const REFUSAL_CACHE_TTL_MS = 1000;

/** Bound on cached entries, so the verify path cannot grow memory without end. */
const CACHE_MAX_ENTRIES = 10_000;

/**
 * The read accelerator's credential: an opaque per-session pseudonym minted
 * beside the access token (CONTEXT.md, Accelerator token).
 *
 * The gateway front is the only caller of `verify`, at roughly one request per
 * leaf block, so every answer — accept or refuse — is cached in process.
 */
@Injectable()
export class GatewayTokenService {
  private readonly ttlSeconds: number;
  private readonly cacheTtlMs: number;
  /** tokenHash → the answer, and the epoch ms it stops being trusted. */
  private readonly cache = new Map<string, { accepted: boolean; until: number }>();

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
  }

  /**
   * Mint this session's pseudonym, then sweep the family's previous one and the
   * account's expired rows. Insert precedes sweep so a failure between them
   * cannot leave the session with no accelerator credential at all.
   */
  async mintForFamily(userId: string, familyId: string): Promise<string> {
    const rawToken = this.entropy.randomBytes(32).toString('hex');
    const tokenHash = sha256Hex(rawToken);
    const now = this.clock.now();
    await this.gatewayTokenRepository.insert({
      userId,
      familyId,
      tokenHash,
      expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
    });
    await this.gatewayTokenRepository
      .createQueryBuilder()
      .delete()
      .where('user_id = :userId', { userId })
      .andWhere('token_hash != :tokenHash', { tokenHash })
      .andWhere('(family_id = :familyId OR expires_at <= :now)', { familyId, now })
      .execute();
    return rawToken;
  }

  /**
   * Whether the presented token still names a live session. Fails closed on
   * anything that is not the minted shape, before the row is looked up.
   */
  async verify(rawToken: string): Promise<boolean> {
    if (!HEX_32_BYTES_RE.test(rawToken)) {
      return false;
    }
    const tokenHash = sha256Hex(rawToken);
    const now = this.clock.now().getTime();
    const cached = this.cache.get(tokenHash);
    if (cached !== undefined && cached.until > now) {
      return cached.accepted;
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
      .setParameter('now', new Date(now))
      .limit(1)
      .getRawOne<{ expires_at: Date }>();

    if (!live) {
      this.remember(tokenHash, false, now + REFUSAL_CACHE_TTL_MS);
      return false;
    }
    // Never past the token's own expiry, so the cache cannot outlive the row.
    this.remember(tokenHash, true, Math.min(live.expires_at.getTime(), now + this.cacheTtlMs));
    return true;
  }

  private remember(tokenHash: string, accepted: boolean, until: number): void {
    // Re-insert so Map iteration order stays oldest-first for the eviction below.
    this.cache.delete(tokenHash);
    this.cache.set(tokenHash, { accepted, until });
    if (this.cache.size > CACHE_MAX_ENTRIES) {
      this.cache.delete(this.cache.keys().next().value as string);
    }
  }
}
