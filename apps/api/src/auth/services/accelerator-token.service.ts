import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { EntityManager, Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { Entropy } from '../../common/entropy';
import { sha256Hex } from '../../common/hash';
import { HEX_32_BYTES_RE } from '../../common/patterns';
import { AcceleratorToken } from '../entities/accelerator-token.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { liveRefreshRowSql } from '../refresh-liveness';
import { resolveAccessTtlSeconds } from './access-ttl';

/**
 * How long a verified token stays trusted in process — the revocation latency,
 * so it is seconds rather than minutes.
 */
const DEFAULT_CACHE_TTL_SECONDS = 10;
const MAX_CACHE_TTL_SECONDS = 60;

/**
 * Refusals age out far faster than acceptances, and are capped separately
 * below: their keys are attacker-chosen, so sharing either budget would let a
 * spray of invented tokens push live sessions out of the cache. One second
 * still collapses a per-block retry storm into a single lookup.
 */
const REFUSAL_CACHE_TTL_MS = 1000;

/** Bounds on cached entries, so the verify path cannot grow memory without end. */
const ACCEPTANCE_CACHE_MAX_ENTRIES = 10_000;
export const REFUSAL_CACHE_MAX_ENTRIES = 1_000;

/** Rows deleted per sweep batch; via ACCELERATOR_TOKEN_SWEEP_BATCH_SIZE. */
const DEFAULT_SWEEP_BATCH_SIZE = 1000;

/** Ceiling on batches per tick, so one sweep cannot run unbounded. */
const SWEEP_MAX_BATCHES = 1000;

/**
 * The read accelerator's credential: an opaque per-session pseudonym minted
 * beside the access token (CONTEXT.md, Accelerator token).
 *
 * The gateway front is the only caller of `verify`, at roughly one request per
 * leaf block, so every answer — accept or refuse — is cached in process.
 */
@Injectable()
export class AcceleratorTokenService {
  private readonly ttlSeconds: number;
  private readonly cacheTtlMs: number;
  private readonly sweepBatchSize: number;
  /** tokenHash → the epoch ms that answer stops being trusted. */
  private readonly accepted = new Map<string, number>();
  private readonly refused = new Map<string, number>();

  constructor(
    private readonly clock: Clock,
    private readonly entropy: Entropy,
    configService: ConfigService,
    @InjectRepository(AcceleratorToken)
    private readonly acceleratorTokenRepository: Repository<AcceleratorToken>
  ) {
    this.ttlSeconds = resolveAccessTtlSeconds(configService);
    this.cacheTtlMs =
      positiveIntConfig(
        configService.get('ACCELERATOR_TOKEN_CACHE_TTL_SECONDS'),
        DEFAULT_CACHE_TTL_SECONDS,
        MAX_CACHE_TTL_SECONDS
      ) * 1000;
    this.sweepBatchSize = positiveIntConfig(
      configService.get('ACCELERATOR_TOKEN_SWEEP_BATCH_SIZE'),
      DEFAULT_SWEEP_BATCH_SIZE
    );
  }

  /**
   * Mint this session's pseudonym, then sweep the family's previous one and the
   * account's expired rows. Runs on the caller's transaction so the pseudonym
   * and the refresh row that defines its validity commit together.
   */
  async mintForFamily(userId: string, familyId: string, manager: EntityManager): Promise<string> {
    const rawToken = this.entropy.randomBytes(32).toString('hex');
    const tokenHash = sha256Hex(rawToken);
    const now = this.clock.now();
    const repository = manager.getRepository(AcceleratorToken);
    await repository.insert({
      userId,
      familyId,
      tokenHash,
      expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
    });
    await repository
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
    if ((this.accepted.get(tokenHash) ?? 0) > now) {
      return true;
    }
    if ((this.refused.get(tokenHash) ?? 0) > now) {
      return false;
    }

    const live = await this.acceleratorTokenRepository
      .createQueryBuilder('accelerator')
      .select('accelerator.expiresAt', 'expires_at')
      // A pseudonym is only as alive as the session that minted it: the family
      // must still hold a live refresh row (see `refreshRowState`).
      .innerJoin(
        RefreshToken,
        'refresh',
        `refresh.family_id = accelerator.family_id AND refresh.user_id = accelerator.user_id AND ${liveRefreshRowSql('refresh')}`
      )
      .where('accelerator.token_hash = :tokenHash', { tokenHash })
      .andWhere('accelerator.expires_at > :now')
      .setParameter('now', new Date(now))
      .limit(1)
      .getRawOne<{ expires_at: Date }>();

    if (!live) {
      remember(this.refused, REFUSAL_CACHE_MAX_ENTRIES, tokenHash, now + REFUSAL_CACHE_TTL_MS);
      return false;
    }
    // Never past the token's own expiry, so the cache cannot outlive the row.
    remember(
      this.accepted,
      ACCEPTANCE_CACHE_MAX_ENTRIES,
      tokenHash,
      Math.min(live.expires_at.getTime(), now + this.cacheTtlMs)
    );
    return true;
  }

  /**
   * Hard-delete every expired row, whoever owns it. A mint only reclaims the
   * minting account's rows, so an account that logs in once and never returns
   * would otherwise keep its row forever.
   */
  async sweepExpired(): Promise<number> {
    const cutoff = this.clock.now();
    let total = 0;
    for (let batch = 0; batch < SWEEP_MAX_BATCHES; batch += 1) {
      const deleted = await this.deleteExpiredBatch(cutoff);
      total += deleted;
      if (deleted < this.sweepBatchSize) {
        break;
      }
    }
    return total;
  }

  /**
   * Postgres has no `DELETE ... LIMIT`, so the batch is bounded by selecting
   * `ctid`s under the cutoff and deleting exactly those; `expires_at` ordering
   * lets `idx_accelerator_tokens_expires_at` drive the scan. `SKIP LOCKED` yields
   * any row a concurrent mint is already deleting, so the two paths take their
   * row locks in whatever order they like without ever forming a cycle.
   */
  private async deleteExpiredBatch(cutoff: Date): Promise<number> {
    const result = await this.acceleratorTokenRepository
      .createQueryBuilder()
      .delete()
      .from(AcceleratorToken)
      .where(
        'ctid IN (SELECT ctid FROM accelerator_tokens WHERE expires_at <= :cutoff ORDER BY expires_at LIMIT :limit FOR UPDATE SKIP LOCKED)',
        { cutoff, limit: this.sweepBatchSize }
      )
      .execute();
    return result.affected ?? 0;
  }
}

function remember(
  cache: Map<string, number>,
  maxEntries: number,
  tokenHash: string,
  until: number
): void {
  // Re-insert so Map iteration order stays oldest-first for the eviction below.
  cache.delete(tokenHash);
  cache.set(tokenHash, until);
  if (cache.size > maxEntries) {
    cache.delete(cache.keys().next().value as string);
  }
}
