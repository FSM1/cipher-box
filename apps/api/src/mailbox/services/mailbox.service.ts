import {
  ConflictException,
  Injectable,
  NotFoundException,
  PayloadTooLargeException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'node:crypto';
import { DataSource, LessThan, QueryFailedError, Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { IdentityService } from '../../auth/services/identity.service';
import {
  acquireAdvisoryLock,
  resolveAdvisoryLockTimeoutMs,
  setAdvisoryLockTimeout,
} from '../../common/advisory-lock';
import { Clock } from '../../common/clock';
import { MailboxMessage } from '../entities/mailbox-message.entity';

/** Spec-fixed hard bound on the sealed blob (blueprint/api.md: <= ~8 KB). */
const MAX_BLOB_BYTES = 8192;

/** 90-day unacked TTL, aligned with record EOLs (blueprint/api.md, Mailbox). */
const TTL_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * Canonical RFC 4122 UUID — the form `gen_random_uuid()` mints for the id
 * column. Ids are always server-minted uuids, so any other shape can never
 * name a row; matching this before the ack delete keeps a malformed id from
 * reaching the `uuid`-typed column (Postgres would raise 22P02 → a 500).
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Read a positive-integer bound from config, falling back to the default for
 * an unset OR garbage value. Both bounds are DoS controls (the pending cap and
 * the poll batch size), so a misconfigured env var must fail closed to the
 * safe default, never silently to NaN (which would disable the cap entirely).
 */
function positiveIntConfig(raw: unknown, fallback: number): number {
  const value = Number(raw);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

export interface PostMessageInput {
  recipientPublicKey: string;
  blob: string;
  idempotencyKey: string;
}

export interface PostMessageResult {
  id: string;
}

export interface PolledMessage {
  id: string;
  receivedAt: string;
  blob: string;
}

/**
 * The integrity-untrusted mailbox (blueprint/api.md, Mailbox).
 *
 * Zero-knowledge: blobs are opaque HPKE-sealed bytes — never decoded, never
 * logged, never signature-checked (that is client-side). Retention is bounded
 * until ack: a per-recipient pending cap (reject-new) and a lazily enforced
 * 90-day TTL, both hard-deletes. Determinism is injected — post time and TTL
 * cutoffs come from the Clock, never `Date.now()`.
 */
@Injectable()
export class MailboxService {
  private readonly pendingCap: number;
  private readonly pollLimit: number;
  private readonly lockTimeoutMs: number;

  constructor(
    @InjectRepository(MailboxMessage)
    private readonly messageRepository: Repository<MailboxMessage>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly identityService: IdentityService,
    private readonly clock: Clock,
    configService: ConfigService
  ) {
    this.pendingCap = positiveIntConfig(configService.get('MAILBOX_PENDING_CAP'), 1000);
    this.pollLimit = positiveIntConfig(configService.get('MAILBOX_POLL_LIMIT'), 100);
    this.lockTimeoutMs = resolveAdvisoryLockTimeoutMs(configService);
  }

  /**
   * Post a sealed blob to a recipient identity publicKey. The sender is the
   * authenticated account; only its hash feeds the idempotency scope, so no
   * durable sender→recipient graph is stored.
   *
   * Posts to unknown recipient pubkeys are rejected — the accepted,
   * rate-limited, exact-pubkey existence oracle (blueprint/api.md). The rate
   * limit lives at the HTTP edge (per-sender throttle); reaching this check at
   * all requires a valid access token, so only a real account can probe it.
   */
  async post(senderPublicKey: string, input: PostMessageInput): Promise<PostMessageResult> {
    const recipientPublicKey = this.identityService.normalizePublicKey(input.recipientPublicKey);

    // Validate the payload before touching the oracle: a malformed request
    // must never learn whether the recipient exists.
    const blob = Buffer.from(input.blob, 'base64');
    if (blob.length > MAX_BLOB_BYTES) {
      throw new PayloadTooLargeException(`Sealed blob exceeds ${MAX_BLOB_BYTES} bytes`);
    }

    const recipient = await this.userRepository.findOne({
      where: { publicKey: recipientPublicKey },
    });
    if (!recipient) {
      throw new NotFoundException('Unknown recipient');
    }

    const idempotencyScope = this.scopeIdempotency(senderPublicKey, input.idempotencyKey);

    // Fast path: an idempotent replay wins even when the mailbox is full, and
    // takes no lock — the common repost case never contends on the per-recipient
    // serialization below.
    const existing = await this.messageRepository.findOne({
      where: { recipientPublicKey, idempotencyScope },
    });
    if (existing) {
      return { id: existing.id };
    }

    try {
      return await this.enforceCapAndInsert(recipientPublicKey, idempotencyScope, blob);
    } catch (error) {
      // The unique (recipient, idempotencyScope) index is the durable dedup
      // backstop under a concurrent double-post: a same-scope insert that races
      // past the in-transaction replay check aborts the transaction, so re-read
      // the committed winner on a fresh statement (outside the rolled-back txn).
      if (error instanceof QueryFailedError) {
        const winner = await this.messageRepository.findOne({
          where: { recipientPublicKey, idempotencyScope },
        });
        if (winner) {
          return { id: winner.id };
        }
      }
      throw error;
    }
  }

  /**
   * The pending-cap enforcement window — purge → count → cap-check → insert —
   * run under a per-recipient transaction-scoped advisory lock so concurrent
   * posts to the SAME recipient serialize. Without the lock the count read and
   * the insert are separate statements: two writers arriving at `cap - 1` could
   * both observe `cap - 1`, both pass the check, and both insert, overshooting
   * the cap (a DoS control). Holding `pg_advisory_xact_lock` across the whole
   * transaction means the second writer blocks until the first commits, then
   * counts the first's committed row before its own check — the overshoot
   * closes structurally, no schema change required. The lock is transaction
   * scoped: Postgres releases it automatically on commit or rollback. The wait
   * is bounded by `lock_timeout` so sustained same-recipient contention cannot
   * fill the pool with blocked waiters (a timed-out waiter surfaces as a 503).
   */
  private async enforceCapAndInsert(
    recipientPublicKey: string,
    idempotencyScope: string,
    blob: Buffer
  ): Promise<PostMessageResult> {
    return this.dataSource.transaction(async (manager) => {
      await setAdvisoryLockTimeout(manager, this.lockTimeoutMs);
      await acquireAdvisoryLock(manager, this.recipientLockKey(recipientPublicKey));
      const repo = manager.getRepository(MailboxMessage);

      // Re-check idempotency now that we hold the lock: a same-scope writer that
      // committed just ahead of us is visible here, so we return its row instead
      // of racing it to a unique-index violation.
      const replay = await repo.findOne({ where: { recipientPublicKey, idempotencyScope } });
      if (replay) {
        return { id: replay.id };
      }

      // Expired rows are dead fuel: purge before counting so a full-of-expired
      // mailbox still accepts new mail (opportunistic housekeeping).
      await this.purgeExpired(recipientPublicKey, repo);

      const pending = await repo.count({ where: { recipientPublicKey } });
      if (pending >= this.pendingCap) {
        throw new ConflictException('Recipient mailbox is full');
      }

      const saved = await repo.save({
        recipientPublicKey,
        idempotencyScope,
        blob,
        receivedAt: this.clock.now(),
      });
      return { id: saved.id };
    });
  }

  /**
   * Poll the caller mailbox: pending messages oldest-first, capped at the
   * poll limit. No sender metadata is returned in the clear — the sealed
   * payload carries the owner-signed sender inside.
   */
  async poll(recipientPublicKey: string): Promise<{ messages: PolledMessage[] }> {
    await this.purgeExpired(recipientPublicKey, this.messageRepository);
    const rows = await this.messageRepository.find({
      where: { recipientPublicKey },
      order: { receivedAt: 'ASC' },
      take: this.pollLimit,
    });
    return {
      messages: rows.map((row) => ({
        id: row.id,
        receivedAt: row.receivedAt.toISOString(),
        blob: Buffer.from(row.blob).toString('base64'),
      })),
    };
  }

  /**
   * Ack = hard delete by id, scoped to the caller mailbox (AGENTS.md: never
   * persist crypto-bearing rows past their consumer). Idempotent and
   * leak-free: acking a gone or foreign id succeeds without side effects.
   */
  async ack(recipientPublicKey: string, id: string): Promise<{ success: boolean }> {
    // A malformed (non-uuid) id can never name a server-minted row, so short
    // out to the documented idempotent success WITHOUT querying Postgres —
    // otherwise the `uuid`-typed id column raises 22P02 (invalid input syntax
    // for uuid) and turns a well-behaved no-op into a 500.
    if (!UUID_RE.test(id)) {
      return { success: true };
    }
    await this.messageRepository.delete({ id, recipientPublicKey });
    return { success: true };
  }

  private async purgeExpired(
    recipientPublicKey: string,
    repo: Repository<MailboxMessage>
  ): Promise<void> {
    const cutoff = new Date(this.clock.now().getTime() - TTL_MS);
    await repo.delete({ recipientPublicKey, receivedAt: LessThan(cutoff) });
  }

  private scopeIdempotency(senderPublicKey: string, idempotencyKey: string): string {
    return createHash('sha256').update(`${senderPublicKey}:${idempotencyKey}`).digest('hex');
  }

  /**
   * Map a recipientPublicKey to a stable signed 64-bit key for
   * `pg_advisory_xact_lock`. sha256 — this file's existing hash of choice (see
   * `scopeIdempotency`) — over the ALREADY-normalized recipient key, then the
   * first 8 bytes read big-endian as a signed BigInt, which is exactly the
   * Postgres `bigint` domain (−2^63 … 2^63−1). Deterministic and process-stable,
   * so every API instance maps a given recipient to the same lock. The
   * acquire helper binds it as a decimal string through `$1::bigint`,
   * sidestepping driver-level BigInt parameter handling. The 8→64-bit
   * truncation admits astronomically rare cross-recipient collisions; the only
   * effect would be two distinct recipients briefly serializing, never a
   * correctness or cap breach.
   */
  private recipientLockKey(recipientPublicKey: string): bigint {
    return createHash('sha256').update(recipientPublicKey).digest().readBigInt64BE(0);
  }
}
