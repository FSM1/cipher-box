import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, In, Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import {
  accountLockKey,
  acquireAdvisoryLocks,
  advisoryLockKey,
  pinDurabilityLockKey,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  setAdvisoryLockTimeout,
  withSessionAdvisoryLock,
} from '../../common/advisory-lock';
import { MailboxMessage } from '../../mailbox/entities/mailbox-message.entity';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';

export interface DeleteAccountResult {
  namesRetired: number;
  pinsRetired: number;
  mailboxPurged: number;
  unpinned: number;
}

const EMPTY_RESULT: DeleteAccountResult = {
  namesRetired: 0,
  pinsRetired: 0,
  mailboxPurged: 0,
  unpinned: 0,
};

/**
 * The account hard-delete cascade (blueprint/api.md, Account lifecycle):
 * immediate hard-delete of the caller's account. Retire every inventory and pin
 * row (refcounted physical unpin), purge the mailbox, delete the auth rows —
 * nothing lingers server-side, never a soft flag (Data-model law).
 *
 * Concurrency is the whole problem here (this is a phantom-INSERT surface, so a
 * row lock is not enough — `FOR UPDATE` cannot see an unborn INSERT). One sorted
 * advisory-lock batch closes every path that could resurrect a row mid-delete,
 * each on the exact key that path already takes:
 *  - `accountLockKey` — a concurrent hosted UPLOAD (its quota gate keys on it);
 *  - `advisoryLockKey(publicKey)` — a concurrent mailbox POST (its recipient
 *    lock is this same shared `advisoryLockKey`);
 *  - `advisoryLockKey(cid)` per pinned CID — the global refcount, so the
 *    survivor check cannot race another account's register/retire/upload of a
 *    shared CID and wrongly unpin it.
 * A concurrent REGISTER is closed by the users-row lock it already takes: taken
 * AFTER the advisory batch (matching register/upload order) so overlapping
 * batches cannot deadlock, and once we commit the delete a blocked register
 * fails closed with "Unknown account" rather than inserting a fresh row.
 *
 * The per-CID batch is seeded from an UNLOCKED pre-read (a single sorted batch is
 * the only deadlock-free way to co-hold `accountLockKey` and the per-CID keys
 * against an upload that takes both together). Under the locks the pin set is
 * re-read as the authority: a CID present there but absent from the pre-read
 * slipped in before the lock and carries no refcount lock, so its unpin decision
 * is unsafe — we fail closed with a retryable 503 (DELETE is idempotent; the
 * retry re-reads the settled set) rather than delete its row and leak the pin.
 *
 * The physical unpin rides the injectable [`PinStore`] seam AFTER commit — never
 * a Kubo call inside the transaction. The in-tx per-CID xact lock releases at
 * commit, so each post-commit unpin re-acquires the SAME session-scoped
 * `pinDurabilityLockKey(cid)` the upload path holds across its commit → pin span,
 * and re-reads the survivor set under it: a pin row that appeared in that gap is
 * a live owner (a concurrent upload physically pinned), so its content is left
 * pinned. It is best-effort — the row bookkeeping is the source of truth, so a
 * Kubo hiccup or lock contention leaves the CID for pin-store GC and never fails
 * the committed delete. `unpinned` counts only CIDs the seam confirms it released
 * (a swallowed unpin failure returns false and is not a release).
 */
@Injectable()
export class AccountService {
  private readonly logger = new Logger(AccountService.name);
  private readonly lockTimeoutMs: number;

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(PinnedCid)
    private readonly pinRepository: Repository<PinnedCid>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly pinStore: PinStore,
    configService: ConfigService
  ) {
    this.lockTimeoutMs = resolveAdvisoryLockTimeoutMs(configService);
  }

  async deleteAccount(accountId: string): Promise<DeleteAccountResult> {
    const account = await this.userRepository.findOne({ where: { id: accountId } });
    if (!account) {
      // The token names no account (already deleted, or stale) — DELETE is
      // idempotent, so report an empty cascade rather than error.
      return EMPTY_RESULT;
    }
    // publicKey is immutable, so this unlocked read is stable; it keys both the
    // mailbox purge and the recipient advisory lock.
    const { publicKey } = account;

    // Seed the per-CID lock batch from an unlocked pre-read. This only chooses
    // which refcount keys to take; the transaction re-reads the true set under
    // the locks and refuses (503) any CID that raced into the gap (see below).
    const preCids = await this.pinRepository.find({ where: { accountId }, select: { cid: true } });
    const cidSet = [...new Set(preCids.map((row) => row.cid))];
    const heldCids = new Set(cidSet);

    const { result, unpinCids } = await runLockGuardedTransaction(
      this.dataSource,
      async (manager) => {
        await setAdvisoryLockTimeout(manager, this.lockTimeoutMs);
        await acquireAdvisoryLocks(manager, [
          accountLockKey(accountId),
          advisoryLockKey(publicKey),
          ...cidSet.map(advisoryLockKey),
        ]);

        const locked = await manager
          .getRepository(User)
          .findOne({ where: { id: accountId }, lock: { mode: 'pessimistic_write' } });
        if (!locked) {
          // A concurrent delete of the same account won the account lock and
          // already removed the row; idempotent success.
          return { result: EMPTY_RESULT, unpinCids: [] as string[] };
        }

        const nameRepo = manager.getRepository(NameInventory);
        const pinRepo = manager.getRepository(PinnedCid);
        const mailboxRepo = manager.getRepository(MailboxMessage);

        // Authoritative set: under the account lock (upload frozen) AND the
        // users-row lock (a concurrent register blocks, then fails closed on its
        // own existence re-check), no new pin row can be born, so this read is
        // the final set. A CID here we did NOT lock above slipped in between the
        // unlocked pre-read and the lock batch — its refcount-zero decision is
        // unguarded, so fail closed (retryable) rather than delete it unpinned.
        const currentCids = [
          ...new Set(
            (await pinRepo.find({ where: { accountId }, select: { cid: true } })).map(
              (row) => row.cid
            )
          ),
        ];
        if (currentCids.some((cid) => !heldCids.has(cid))) {
          throw new ServiceUnavailableException(
            'Concurrent pin write during delete; retry shortly'
          );
        }

        const namesRetired = (await nameRepo.delete({ accountId })).affected ?? 0;
        const pinsRetired = (await pinRepo.delete({ accountId })).affected ?? 0;

        // Under the per-CID locks, a held CID with no surviving row across all
        // accounts is at global refcount zero. Co-registered shared content
        // survives via other accounts' rows (union liveness).
        const survivors = currentCids.length
          ? await pinRepo.find({ where: { cid: In(currentCids) } })
          : [];
        const surviving = new Set(survivors.map((row) => row.cid));
        const unpinCids = currentCids.filter((cid) => !surviving.has(cid));

        // Mailbox rows are keyed by recipient publicKey with no FK to users — purge
        // explicitly. Auth rows (auth_methods, refresh_tokens) cascade on the
        // users delete via their onDelete: 'CASCADE'.
        const mailboxPurged =
          (await mailboxRepo.delete({ recipientPublicKey: publicKey })).affected ?? 0;
        await manager.getRepository(User).delete({ id: accountId });

        return {
          result: { namesRetired, pinsRetired, mailboxPurged, unpinned: 0 },
          unpinCids,
        };
      }
    );

    // Best-effort physical unpin after commit, each serialized on the upload
    // path's per-CID durability lock and gated on a survivor recount under it
    // (see class doc). Contention or a Kubo hiccup leaves the CID for GC.
    let unpinned = 0;
    for (const cid of unpinCids) {
      try {
        const released = await withSessionAdvisoryLock(
          this.dataSource,
          pinDurabilityLockKey(cid),
          this.lockTimeoutMs,
          async () => {
            // A pin row visible under the durability lock is a live owner that
            // pinned into the post-commit gap — leave its content pinned.
            if (await this.pinRepository.findOne({ where: { cid } })) {
              return false;
            }
            return this.pinStore.unpin(cid);
          }
        );
        if (released) {
          unpinned += 1;
        }
      } catch (error) {
        this.logger.warn(`post-delete unpin for ${cid} skipped: ${String(error)}`);
      }
    }

    return { ...result, unpinned };
  }
}
