import {
  ConflictException,
  Injectable,
  NotFoundException,
  PayloadTooLargeException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'node:crypto';
import { LessThan, QueryFailedError, Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { IdentityService } from '../../auth/services/identity.service';
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

  constructor(
    @InjectRepository(MailboxMessage)
    private readonly messageRepository: Repository<MailboxMessage>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly identityService: IdentityService,
    private readonly clock: Clock,
    configService: ConfigService
  ) {
    this.pendingCap = positiveIntConfig(configService.get('MAILBOX_PENDING_CAP'), 1000);
    this.pollLimit = positiveIntConfig(configService.get('MAILBOX_POLL_LIMIT'), 100);
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

    // Idempotent replay wins even when the mailbox is full.
    const existing = await this.messageRepository.findOne({
      where: { recipientPublicKey, idempotencyScope },
    });
    if (existing) {
      return { id: existing.id };
    }

    // Expired rows are dead fuel: purge before counting so a full-of-expired
    // mailbox still accepts new mail (opportunistic housekeeping).
    await this.purgeExpired(recipientPublicKey);

    const pending = await this.messageRepository.count({ where: { recipientPublicKey } });
    if (pending >= this.pendingCap) {
      throw new ConflictException('Recipient mailbox is full');
    }

    try {
      const saved = await this.messageRepository.save({
        recipientPublicKey,
        idempotencyScope,
        blob,
        receivedAt: this.clock.now(),
      });
      return { id: saved.id };
    } catch (error) {
      // The unique (recipient, idempotencyScope) index is the durable dedup
      // backstop under a concurrent double-post; re-read and return the winner.
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
   * Poll the caller mailbox: pending messages oldest-first, capped at the
   * poll limit. No sender metadata is returned in the clear — the sealed
   * payload carries the owner-signed sender inside.
   */
  async poll(recipientPublicKey: string): Promise<{ messages: PolledMessage[] }> {
    await this.purgeExpired(recipientPublicKey);
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

  private async purgeExpired(recipientPublicKey: string): Promise<void> {
    const cutoff = new Date(this.clock.now().getTime() - TTL_MS);
    await this.messageRepository.delete({ recipientPublicKey, receivedAt: LessThan(cutoff) });
  }

  private scopeIdempotency(senderPublicKey: string, idempotencyKey: string): string {
    return createHash('sha256').update(`${senderPublicKey}:${idempotencyKey}`).digest('hex');
  }
}
