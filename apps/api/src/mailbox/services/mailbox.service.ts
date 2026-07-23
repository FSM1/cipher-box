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
  advisoryLockKey,
  boundedAcquire,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
} from '../../common/advisory-lock';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { MailboxMessage } from '../entities/mailbox-message.entity';

/** Spec-fixed hard bound on the sealed blob (blueprint/api.md: <= ~8 KB). */
const MAX_BLOB_BYTES = 8192;

/** 90-day unacked TTL, aligned with record EOLs (blueprint/api.md, Mailbox). */
const TTL_MS = 90 * 24 * 60 * 60 * 1000;

/** Rows deleted per global-sweep batch; via MAILBOX_SWEEP_BATCH_SIZE. */
const DEFAULT_SWEEP_BATCH_SIZE = 1000;

/**
 * Internal "don't loop forever" guard on batches per sweep run — not a per-deploy
 * knob. The loop already drains on `deleted < batchSize`; this only caps a
 * pathological backlog, leaving any remainder for the next scheduled run.
 */
export const SWEEP_MAX_BATCHES = 1000;

/**
 * Canonical RFC 4122 UUID — the form `gen_random_uuid()` mints for the id
 * column. Ids are always server-minted uuids, so any other shape can never
 * name a row; matching this before the ack delete keeps a malformed id from
 * reaching the `uuid`-typed column (Postgres would raise 22P02 → a 500).
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  private readonly sweepBatchSize: number;

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
    this.sweepBatchSize = positiveIntConfig(
      configService.get('MAILBOX_SWEEP_BATCH_SIZE'),
      DEFAULT_SWEEP_BATCH_SIZE
    );
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
   * The count-sees-committed-writer reasoning assumes READ COMMITTED.
   */
  private async enforceCapAndInsert(
    recipientPublicKey: string,
    idempotencyScope: string,
    blob: Buffer
  ): Promise<PostMessageResult> {
    return runLockGuardedTransaction(this.dataSource, async (manager) => {
      await boundedAcquire(
        manager,
        [this.recipientLockKey(recipientPublicKey)],
        this.lockTimeoutMs
      );
      const repo = manager.getRepository(MailboxMessage);

      // Re-check idempotency now that we hold the lock: a same-scope writer that
      // committed just ahead of us is visible here, so we return its row instead
      // of racing it to a unique-index violation.
      const replay = await repo.findOne({ where: { recipientPublicKey, idempotencyScope } });
      if (replay) {
        return { id: replay.id };
      }

      // Re-verify the recipient still exists while holding the recipient lock,
      // not only at the unlocked oracle above: the account hard-delete cascade
      // holds this same key while it purges the mailbox and deletes the account,
      // so a post that raced the delete observes the committed deletion here and
      // fails closed rather than resurrecting a row for a gone account (mailbox
      // rows have no FK to cascade them). The lock (held until this transaction
      // commits) bars any delete between this re-check and the insert below.
      const recipient = await this.userRepository.findOne({
        where: { publicKey: recipientPublicKey },
      });
      if (!recipient) {
        throw new NotFoundException('Unknown recipient');
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

  /**
   * The global, recipient-less TTL sweep the scheduled worker drives (#667): the
   * lazy `purgeExpired` only fires on a recipient's own post/poll, so a dormant
   * mailbox keeps expired rows forever. This makes the 90-day bound a hard
   * guarantee independent of activity.
   *
   * The cutoff is one Clock snapshot for the whole run (deterministic, testable),
   * and deletes are batched by `ctid` — bounded rows per statement, looping until
   * a short batch signals drained — so the sweep never takes a long table lock or
   * bloats a single transaction on a large backlog. It is safe to interleave with
   * post/poll/lazy purge: a concurrent post writes a fresh `received_at` (>=
   * cutoff) that this WHERE can never match, and a row another path already
   * deleted simply isn't re-counted. Overlap is prevented in-process by the
   * scheduler's in-flight guard (the republisher's mechanism); a cross-instance
   * overlap is harmless because the delete is idempotent. Returns the number of
   * rows deleted.
   */
  async sweepExpired(): Promise<number> {
    const cutoff = new Date(this.clock.now().getTime() - TTL_MS);
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
   * Delete up to one batch of globally-expired rows. Postgres has no
   * `DELETE ... LIMIT`, so the batch is bounded by selecting `ctid`s under the
   * cutoff and deleting exactly those; `received_at` ordering lets the
   * `idx_mailbox_received_at` index drive the scan. Returns the rows deleted.
   */
  private async deleteExpiredBatch(cutoff: Date): Promise<number> {
    const result = await this.messageRepository
      .createQueryBuilder()
      .delete()
      .from(MailboxMessage)
      .where(
        'ctid IN (SELECT ctid FROM mailbox_messages WHERE received_at < :cutoff ORDER BY received_at LIMIT :limit)',
        { cutoff, limit: this.sweepBatchSize }
      )
      .execute();
    return result.affected ?? 0;
  }

  private scopeIdempotency(senderPublicKey: string, idempotencyKey: string): string {
    return createHash('sha256').update(`${senderPublicKey}:${idempotencyKey}`).digest('hex');
  }

  /**
   * The per-recipient advisory-lock key over the ALREADY-normalized recipient
   * key. This MUST be the shared `advisoryLockKey` (not a private copy): the
   * account hard-delete cascade serializes against a concurrent post by taking
   * `advisoryLockKey(publicKey)`, so the two derive the recipient key from one
   * source — the resurrection guard is structural, not an asserted invariant.
   */
  private recipientLockKey(recipientPublicKey: string): bigint {
    return advisoryLockKey(recipientPublicKey);
  }
}
