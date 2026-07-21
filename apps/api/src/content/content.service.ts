import {
  Injectable,
  Logger,
  PayloadTooLargeException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, EntityManager } from 'typeorm';
import { User } from '../auth/entities/user.entity';
import {
  acquireAdvisoryLocks,
  advisoryLockKey,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  setAdvisoryLockTimeout,
  withSessionAdvisoryLock,
} from '../common/advisory-lock';
import { PinnedCid } from '../registry/entities/pinned-cid.entity';
import { PinStore } from '../registry/pin-store';
import {
  byteConfigBigInt,
  DEFAULT_QUOTA_BYTES,
  exceedsQuota,
  resolveLimitBytes,
  sumPinnedBytes,
} from '../registry/quota';

/** A stored pin outcome plus whether THIS upload created the row (drives the pin). */
interface RegisterOutcome {
  cid: string;
  size: number;
  created: boolean;
}

export interface UploadResult {
  cid: string;
  size: number;
}

/**
 * The hosted ingress upload path (blueprint/api.md, Content plane): pin opaque
 * bytes to CipherBox Kubo, quota-gated, registering the pin row in the same
 * traversal. The API is zero-knowledge — it pins bytes it never inspects.
 *
 * Concurrency (two shared resources under contention):
 *  - the per-account quota SUM — a check-then-act serialized by a per-account
 *    advisory lock so two concurrent uploads cannot both pass at the limit;
 *  - the per-CID pin refcount — serialized by the SAME per-CID advisory lock
 *    the registry's register/retire take, so an insert here can never race an
 *    unpin there. Both keys acquire in one sorted batch (deadlock-free).
 *
 * The DB transaction is the source of truth; the durable Kubo pin fires AFTER
 * commit. Byte-pin + row register stay all-or-nothing: a post-commit pin
 * failure compensates by retiring the row it just added. A per-CID SESSION lock
 * (distinct `pin-durability:` key) spans commit → pin → compensate, so the in-tx
 * xact lock releasing at commit cannot let a concurrent same-CID upload observe
 * a committed row whose pin is still pending and return success for bytes that
 * were never durably pinned.
 */
@Injectable()
export class ContentService {
  private readonly logger = new Logger(ContentService.name);
  private readonly defaultLimitBytes: bigint;
  private readonly lockTimeoutMs: number;

  constructor(
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly pinStore: PinStore,
    configService: ConfigService
  ) {
    this.defaultLimitBytes = byteConfigBigInt(
      configService.get('QUOTA_DEFAULT_BYTES'),
      DEFAULT_QUOTA_BYTES
    );
    this.lockTimeoutMs = resolveAdvisoryLockTimeoutMs(configService);
  }

  async upload(accountId: string, bytes: Buffer): Promise<UploadResult> {
    const size = bytes.byteLength;
    // Phase 1 — derive the CID with no durable side effect (only-hash), so the
    // ledger below can key on it before any bytes are pinned.
    const cid = await this.pinStore.hash(bytes);

    // Serialize the whole commit → pin → compensate span per CID with a session
    // lock, so a concurrent same-CID upload cannot observe a committed-but-not-
    // yet-pinned row and return success for it (the in-tx xact lock releases at
    // commit, too early to cover the post-commit pin).
    return withSessionAdvisoryLock(
      this.dataSource,
      pinDurabilityLockKey(cid),
      this.lockTimeoutMs,
      () => this.registerAndPin(accountId, cid, size, bytes)
    );
  }

  private async registerAndPin(
    accountId: string,
    cid: string,
    size: number,
    bytes: Buffer
  ): Promise<UploadResult> {
    // Phase 2 — the source of truth: gate + register under the account and CID
    // advisory locks, atomically.
    const outcome = await runLockGuardedTransaction(this.dataSource, (manager) =>
      this.registerPin(manager, accountId, cid, size)
    );

    // Phase 3 — durable pin AFTER commit. Byte-pin + register are all-or-nothing:
    // a pin failure (or a CID mismatch) compensates by retiring the new row.
    if (outcome.created) {
      let pinnedCid: string;
      try {
        pinnedCid = await this.pinStore.pin(bytes);
      } catch {
        await this.compensate(accountId, cid);
        throw new ServiceUnavailableException('Pin store unavailable; upload not durable');
      }
      if (pinnedCid !== cid) {
        // Fail closed: the row keys on `cid`; a mismatch means Kubo pinned bytes
        // under a different CID than the ledger references.
        await this.compensate(accountId, cid);
        throw new ServiceUnavailableException('Pin CID mismatch; upload rejected');
      }
    }

    return { cid: outcome.cid, size: outcome.size };
  }

  private async registerPin(
    manager: EntityManager,
    accountId: string,
    cid: string,
    size: number
  ): Promise<RegisterOutcome> {
    await setAdvisoryLockTimeout(manager, this.lockTimeoutMs);
    // Account key serializes the quota check-then-act; the CID key serializes the
    // pin-row insert against a concurrent register/retire of the same CID.
    await acquireAdvisoryLocks(manager, [accountLockKey(accountId), advisoryLockKey(cid)]);

    const userRepo = manager.getRepository(User);
    const pinRepo = manager.getRepository(PinnedCid);

    const user = await userRepo.findOne({ where: { id: accountId } });
    if (!user) {
      throw new UnauthorizedException('Unknown account');
    }
    // byo is read unlocked: the account lock serializes the quota gate; a racing
    // BYO toggle only mis-stamps advisory on the new row, which self-heals.
    const advisory = user.byo;

    const existing = await pinRepo.findOne({ where: { accountId, cid } });
    if (existing) {
      // Idempotent re-upload: the CID already counts — no gate, no new charge.
      return { cid, size: Number(existing.size), created: false };
    }

    if (!advisory) {
      const used = await sumPinnedBytes(pinRepo, accountId);
      const limit = resolveLimitBytes(user.quotaLimitOverride, this.defaultLimitBytes);
      if (exceedsQuota(used, BigInt(size), limit)) {
        throw new PayloadTooLargeException('Upload exceeds the account storage quota');
      }
    }

    await pinRepo.insert({ accountId, cid, size: size.toString(), advisory });
    return { cid, size, created: true };
  }

  /**
   * Retire a pin row a failed durable pin left dangling, unpinning at global
   * refcount zero — under the same per-CID lock discipline as the registry. A
   * compensation failure is logged, never surfaced: a stranded row is only a
   * registered orphan the republisher GCs, and it must not mask the pin error.
   */
  private async compensate(accountId: string, cid: string): Promise<void> {
    try {
      const unpin = await runLockGuardedTransaction(this.dataSource, async (manager) => {
        await setAdvisoryLockTimeout(manager, this.lockTimeoutMs);
        await acquireAdvisoryLocks(manager, [advisoryLockKey(cid)]);
        const pinRepo = manager.getRepository(PinnedCid);
        await pinRepo.delete({ accountId, cid });
        const survivors = await pinRepo.find({ where: { cid } });
        return survivors.length === 0;
      });
      if (unpin) {
        await this.pinStore.unpin(cid);
      }
    } catch (error) {
      this.logger.warn(`compensation for ${cid} failed: ${String(error)}`);
    }
  }
}

/** Namespaced account advisory key: `account:` prevents any UUID/CID key collision. */
function accountLockKey(accountId: string): bigint {
  return advisoryLockKey(`account:${accountId}`);
}

/**
 * Namespaced session lock for the post-commit pin/compensation window. A
 * DISTINCT key from the plain CID xact lock: the same upload holds both (session
 * lock on its own connection, xact lock on the tx connection), and same-key
 * session-vs-xact locks across connections would self-deadlock.
 */
function pinDurabilityLockKey(cid: string): bigint {
  return advisoryLockKey(`pin-durability:${cid}`);
}
