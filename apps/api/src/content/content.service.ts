import {
  BadRequestException,
  ConflictException,
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
  accountLockKey,
  advisoryLockKey,
  boundedAcquire,
  pinDurabilityLockKey,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  withSessionAdvisoryLock,
} from '../common/advisory-lock';
import { resolveDbPoolSize } from '../common/db-pool';
import { Semaphore } from '../common/semaphore';
import { PinReference } from '../registry/entities/pin-reference.entity';
import { PinnedCid } from '../registry/entities/pinned-cid.entity';
import { PinCidMismatchError, PinStore } from '../registry/pin-store';
import {
  byteConfigBigInt,
  DEFAULT_QUOTA_BYTES,
  exceedsQuota,
  resolveLimitBytes,
  sumHostedBytes,
} from '../registry/quota';
import { QUOTA_EXCEEDED, uploadTooLargeBody } from './upload-error-codes';

/**
 * Max uploads admitted concurrently to the pin path (`CONTENT_PIN_CONCURRENCY`).
 * Each admitted upload holds one pooled DB connection (the session lock) across
 * its ~30s Kubo pin, and transiently a second (the Phase-2 tx) — so a pin burst
 * could otherwise tie up the whole pool and 503 unrelated routes.
 */
const DEFAULT_PIN_CONCURRENCY = 4;

export interface ResolvedPinConcurrency {
  ceiling: number;
  /** The configured value before clamping, when it had to be lowered. */
  clampedFrom?: number;
}

/**
 * The pin-admission ceiling, clamped so `2 × ceiling ≤ poolSize` always holds
 * (an admitted upload holds its session-lock connection across the pin AND
 * borrows a second for the commit tx, so it needs 2 pooled connections to make
 * progress). Deriving the ceiling from the pool size makes that invariant
 * structural — config drift (an over-large ceiling) can no longer silently
 * reintroduce pool exhaustion. A pool of 1 cannot host even one upload without
 * self-deadlocking on its second connection, so the safe max floors to 0 there
 * and the pin path is refused (upload() fails closed) rather than deadlocked.
 */
export function resolvePinConcurrency(configService: ConfigService): ResolvedPinConcurrency {
  const raw = configService.get<string | number>('CONTENT_PIN_CONCURRENCY');
  let configured = DEFAULT_PIN_CONCURRENCY;
  if (raw !== undefined && raw !== null && String(raw).trim() !== '') {
    const value = Number(raw);
    if (Number.isInteger(value) && value >= 1) {
      configured = value;
    }
  }
  const safeMax = Math.floor(resolveDbPoolSize(configService) / 2);
  const ceiling = Math.min(configured, safeMax);
  return ceiling < configured ? { ceiling, clampedFrom: configured } : { ceiling };
}

/**
 * A stored pin outcome. `created` drives the durable pin — true both when this
 * upload inserted a fresh row and when it PROMOTED a registry-only row (size 0,
 * never hosted-pinned) to a real hosted pin. `promoted` tells compensation to
 * revert just the size charge on that pre-existing row rather than delete it.
 */
interface RegisterOutcome {
  size: number;
  created: boolean;
  promoted: boolean;
}

export interface UploadResult {
  cid: string;
  size: number;
}

/**
 * The hosted ingress upload path (blueprint/api.md, Content plane): pin opaque
 * bytes to CipherBox Kubo under the address the caller declared for them,
 * quota-gated, registering the pin row in the same traversal. The API is
 * zero-knowledge — it pins bytes it never inspects and computes no content
 * address of its own. Only hosted accounts may ingress here: a BYO account pins
 * to its own provider and its bytes bypass the API, so a BYO upload is refused
 * (409) rather than pinned to hosted Kubo off the quota's books.
 *
 * Concurrency (two shared resources under contention):
 *  - the per-account quota SUM — a check-then-act serialized by a per-account
 *    advisory lock so two concurrent uploads cannot both pass at the limit;
 *  - the per-CID pin refcount — serialized by the SAME per-CID advisory lock
 *    the registry's register/retire take, so an insert here can never race an
 *    unpin there. Both keys acquire in one sorted batch (deadlock-free).
 *
 * A register-only row (CID membership recorded at size 0 with no hosted bytes)
 * is NOT a completed pin: an upload of the matching bytes promotes it — pinning
 * and charging it — rather than trusting content Kubo never held.
 *
 * The DB transaction is the source of truth; the durable Kubo pin fires AFTER
 * commit. Byte-pin + row register stay all-or-nothing: a post-commit pin failure
 * compensates by retiring a row it inserted, or reverting a promoted row's size
 * charge (the pre-existing registration survives). A per-CID SESSION lock
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
  /** Bounds concurrent pin-path connections so the pin can't starve the pool. */
  private readonly pinSlots: Semaphore;
  /** 0 when the pool is too small (< 2) to host one upload — the path fails closed. */
  private readonly pinCeiling: number;

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
    const pinConcurrency = resolvePinConcurrency(configService);
    this.pinCeiling = pinConcurrency.ceiling;
    if (pinConcurrency.ceiling === 0) {
      this.logger.error(
        'DB pool too small for the content pin path (needs DB_POOL_SIZE >= 2); hosted uploads will be refused with 503'
      );
    } else if (pinConcurrency.clampedFrom !== undefined) {
      this.logger.warn(
        `CONTENT_PIN_CONCURRENCY=${pinConcurrency.clampedFrom} exceeds the safe bound for the DB pool; clamped to ${pinConcurrency.ceiling} to preserve pool headroom`
      );
    }
    this.pinSlots = new Semaphore(pinConcurrency.ceiling);
  }

  async upload(accountId: string, cid: string, bytes: Buffer): Promise<UploadResult> {
    // Fail closed on a pool too small (< 2 connections) to host one upload: the
    // pin path needs its session-lock connection AND a second for the commit tx,
    // so admitting a request here would self-deadlock waiting for the second.
    if (this.pinCeiling === 0) {
      throw new ServiceUnavailableException('Content pin path unavailable; DB pool too small');
    }
    const size = bytes.byteLength;

    // Admit at most `pinSlots` uploads into the session-lock → pin → compensate
    // span at once. That span holds a pooled connection across the external pin,
    // so an unbounded burst would otherwise exhaust the DB pool; the ceiling
    // reserves connections for every other route while the pin is in flight.
    return this.pinSlots.run(() =>
      // Per-CID session lock spans commit → pin → compensate (see class doc).
      withSessionAdvisoryLock(this.dataSource, pinDurabilityLockKey(cid), this.lockTimeoutMs, () =>
        this.registerAndPin(accountId, cid, size, bytes)
      )
    );
  }

  private async registerAndPin(
    accountId: string,
    cid: string,
    size: number,
    bytes: Buffer
  ): Promise<UploadResult> {
    // Phase 1 — the source of truth: gate + register under the account and CID
    // advisory locks, atomically.
    const outcome = await runLockGuardedTransaction(this.dataSource, (manager) =>
      this.registerPin(manager, accountId, cid, size)
    );

    // Phase 2 — durable pin AFTER commit, under the declared CID. Byte-pin +
    // register are all-or-nothing: a pin failure compensates — retiring a row it
    // inserted, or reverting a promoted row's size charge. A declared CID that
    // does not address the bytes is a permanent caller fault (400), not a
    // retriable outage (503).
    if (outcome.created) {
      try {
        await this.pinStore.pin(cid, bytes);
      } catch (error) {
        await this.compensate(accountId, cid, outcome.promoted);
        if (error instanceof PinCidMismatchError) {
          throw new BadRequestException('Declared CID does not address the uploaded bytes');
        }
        throw new ServiceUnavailableException('Pin store unavailable; upload not durable');
      }
    }

    return { cid, size: outcome.size };
  }

  private async registerPin(
    manager: EntityManager,
    accountId: string,
    cid: string,
    size: number
  ): Promise<RegisterOutcome> {
    // Account key serializes the quota check-then-act; the CID key serializes the
    // pin-row insert against a concurrent register/retire of the same CID.
    await boundedAcquire(
      manager,
      [accountLockKey(accountId), advisoryLockKey(cid)],
      this.lockTimeoutMs
    );

    const userRepo = manager.getRepository(User);
    const pinRepo = manager.getRepository(PinnedCid);

    // Read BYO under a users-row lock (FOR UPDATE), the same synchronization
    // point registry.register uses: setByo toggles the flag with a bare UPDATE
    // that takes no advisory lock, so only the row lock serializes it against
    // this read. Without it a concurrent PATCH /account/byo could commit true
    // after an unlocked read of false and let a BYO account pin to hosted Kubo,
    // or commit false after a read of true and 409 a valid hosted upload.
    const user = await userRepo.findOne({
      where: { id: accountId },
      lock: { mode: 'pessimistic_write' },
    });
    if (!user) {
      throw new UnauthorizedException('Unknown account');
    }
    // Fail closed at hosted ingress for a BYO account: its bytes belong on its
    // own provider and bypass the API (blueprint/api.md, Content plane). Pinning
    // them to hosted Kubo off an advisory, uncounted row would be free hosted
    // storage, so refuse rather than pin. The row lock above makes this read and
    // the quota gate below atomic w.r.t. setByo, so a hosted upload past this
    // point always registers an AUTHORITATIVE (advisory=false) row.
    if (user.byo) {
      throw new ConflictException('Hosted ingress is unavailable for BYO accounts');
    }

    const existing = await pinRepo.findOne({ where: { accountId, cid } });
    // A registry-only row (register() records CID membership at size 0 with no
    // bytes on hosted Kubo) is NOT a completed hosted pin: only `size > 0` marks
    // durably-pinned, charged bytes. Short-circuit as idempotent only for the
    // latter; promote the former so the bytes are actually pinned and charged
    // rather than trusted for content Kubo never held.
    if (existing && BigInt(existing.size) > 0n) {
      // Idempotent re-upload: the CID already counts — no gate, no new charge.
      return { size: Number(existing.size), created: false, promoted: false };
    }

    // Gate against AUTHORITATIVE rows only: stale advisory rows an account kept
    // after toggling BYO off live on its own provider, not the hosted quota. A
    // promoted row is still size 0 here, so it adds nothing to `used` — the gate
    // charges the incoming size exactly once, never double-counting.
    const used = await sumHostedBytes(pinRepo, accountId);
    const limit = resolveLimitBytes(user.quotaLimitOverride, this.defaultLimitBytes);
    if (exceedsQuota(used, BigInt(size), limit)) {
      throw new PayloadTooLargeException(
        uploadTooLargeBody(QUOTA_EXCEEDED, 'Upload exceeds the account storage quota')
      );
    }

    if (existing) {
      // Promote the registry-only row: stamp the real size and mark it
      // authoritative so the charge lands in the hosted sum, then drive the
      // durable pin (`created`) exactly as a fresh insert would.
      await pinRepo.update({ accountId, cid }, { size: size.toString(), advisory: false });
      return { size, created: true, promoted: true };
    }

    await pinRepo.insert({ accountId, cid, size: size.toString(), advisory: false });
    return { size, created: true, promoted: false };
  }

  /**
   * Undo a failed durable pin. For a row THIS upload inserted that no record
   * references, retire it, unpinning at global refcount zero — same per-CID
   * lock discipline as the registry. For a row a registration holds — PROMOTED
   * from a pre-existing registry-only row, or claimed by a register that
   * committed inside the upload window — revert only the size charge back to 0:
   * the registration must survive a
   * transient pin failure, and nothing was durably pinned, so no unpin fires. A
   * compensation failure is logged, never surfaced: a stranded charge/row is
   * only a registered orphan the republisher GCs, and it must not mask the pin
   * error.
   */
  private async compensate(accountId: string, cid: string, promoted: boolean): Promise<void> {
    try {
      const unpin = await runLockGuardedTransaction(this.dataSource, async (manager) => {
        await boundedAcquire(manager, [advisoryLockKey(cid)], this.lockTimeoutMs);
        const pinRepo = manager.getRepository(PinnedCid);
        // registerPin commits its row before the pin call, so a register can
        // claim this CID under its own record while that call runs. Recount the
        // edges under the lock: deleting the row would drop a live claim.
        const registered =
          promoted || (await manager.getRepository(PinReference).countBy({ accountId, cid })) > 0;
        if (registered) {
          await pinRepo.update({ accountId, cid }, { size: '0' });
          return false;
        }
        await pinRepo.delete({ accountId, cid });
        const survivors = await pinRepo.find({ where: { cid } });
        return survivors.length === 0;
      });
      if (unpin) {
        await this.pinStore.unpin(cid);
      }
    } catch (error) {
      // Alertable: a stranded charged row makes every later upload of these
      // bytes short-circuit as already-pinned, for a pin that never landed.
      this.logger.error(`compensation for ${cid} failed: ${String(error)}`);
    }
  }
}
