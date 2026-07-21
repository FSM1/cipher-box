import { Injectable, Logger } from '@nestjs/common';
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
 * Pin CIDs drained per chunk transaction. The account's pin count is bounded by
 * quota BYTES, not count, so a large account of small files is tens of thousands
 * of CIDs; locking them all in one transaction blows `lock_timeout` and holds a
 * five-figure advisory-lock set, making the account permanently undeletable.
 * Draining in bounded chunks keeps every transaction's lock set and round-trip
 * small so an account of any size stays deletable.
 */
export const DELETE_CHUNK_SIZE = 256;

type ChunkOutcome =
  | { kind: 'gone' }
  | { kind: 'more' }
  | { kind: 'chunk'; pinsRetired: number; unpinCids: string[] }
  | { kind: 'final'; namesRetired: number; mailboxPurged: number };

/**
 * The account hard-delete cascade (blueprint/api.md, Account lifecycle):
 * immediate hard-delete of the caller's account — retire every inventory and pin
 * row (refcounted physical unpin), purge the mailbox, delete the auth rows.
 * Nothing lingers server-side, never a soft flag (Data-model law).
 *
 * Concurrency is a phantom-INSERT surface: a row lock is not enough because
 * `FOR UPDATE` cannot see an unborn INSERT. Each pin chunk takes ONE sorted
 * advisory-lock batch that closes every path resurrecting a row mid-delete, on
 * the exact key that path already takes:
 *  - `accountLockKey` — a concurrent hosted UPLOAD (its quota gate keys on it);
 *  - `advisoryLockKey(cid)` per chunk CID — the global refcount, so the survivor
 *    check cannot race another account's register/retire/upload of a shared CID
 *    and wrongly unpin it. `register` takes this same key but NO post-commit
 *    durability lock, so this in-tx lock — not the recount below — is what makes
 *    the delete → survivor read the authority against a concurrent register.
 * A concurrent REGISTER is further closed by the users-row lock it takes, held
 * AFTER the advisory batch (matching register/upload order) so overlapping
 * batches cannot deadlock.
 *
 * The pin set is drained in bounded chunks, each chunk deleting and unpinning
 * ONLY the CIDs it locked — so no unlocked phantom is ever deleted and no 503
 * pre-read guard is needed. The account lock releases between chunks; a CID the
 * account adds meanwhile is simply picked up by a later chunk. The residue
 * (names, mailbox, user row) is removed only once a chunk observes zero pins
 * UNDER the account + users-row lock, where no new pin can be born, so the FK
 * cascade on the user delete never strands an un-unpinned row. That residue step
 * also takes `advisoryLockKey(publicKey)` — the mailbox POST's recipient key —
 * so a post cannot resurrect an orphan row across the purge + user delete.
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

    const totals: DeleteAccountResult = { ...EMPTY_RESULT };
    for (;;) {
      // Seed the chunk's sorted lock batch from an unlocked pre-read; the chunk
      // deletes and unpins ONLY these locked CIDs.
      const chunkCids = [
        ...new Set(
          (
            await this.pinRepository.find({
              where: { accountId },
              select: { cid: true },
              take: DELETE_CHUNK_SIZE,
            })
          ).map((row) => row.cid)
        ),
      ];

      const outcome = await this.deleteChunk(accountId, publicKey, chunkCids);
      if (outcome.kind === 'gone') {
        break;
      }
      if (outcome.kind === 'more') {
        continue;
      }
      if (outcome.kind === 'chunk') {
        totals.pinsRetired += outcome.pinsRetired;
        totals.unpinned += await this.unpinAfterCommit(outcome.unpinCids);
        continue;
      }
      totals.namesRetired += outcome.namesRetired;
      totals.mailboxPurged += outcome.mailboxPurged;
      break;
    }

    return totals;
  }

  /**
   * One bounded step of the cascade. With `chunkCids` non-empty it retires that
   * locked slice of pin rows and returns the CIDs at global refcount zero. With
   * it empty it removes the residue (names, mailbox, user row) — but only if no
   * pin raced in after the unlocked pre-read; a straggler seen under the lock
   * defers to another draining pass (`more`) so the FK cascade never strands an
   * un-unpinned pin.
   */
  private async deleteChunk(
    accountId: string,
    publicKey: string,
    chunkCids: string[]
  ): Promise<ChunkOutcome> {
    return runLockGuardedTransaction(this.dataSource, async (manager) => {
      await setAdvisoryLockTimeout(manager, this.lockTimeoutMs);
      // The residue step (empty chunk) also takes `advisoryLockKey(publicKey)` —
      // the recipient key a mailbox POST holds across its existence re-check and
      // insert — so a post racing the mailbox purge + user delete observes the
      // committed deletion and fails closed rather than resurrecting an orphan
      // row (mailbox rows have no FK to cascade them).
      await acquireAdvisoryLocks(manager, [
        accountLockKey(accountId),
        ...(chunkCids.length === 0 ? [advisoryLockKey(publicKey)] : []),
        ...chunkCids.map(advisoryLockKey),
      ]);

      const locked = await manager
        .getRepository(User)
        .findOne({ where: { id: accountId }, lock: { mode: 'pessimistic_write' } });
      if (!locked) {
        // A concurrent delete of the same account won the account lock and
        // already removed the row; idempotent success.
        return { kind: 'gone' };
      }

      const nameRepo = manager.getRepository(NameInventory);
      const pinRepo = manager.getRepository(PinnedCid);
      const mailboxRepo = manager.getRepository(MailboxMessage);

      if (chunkCids.length === 0) {
        // Under the account + users-row lock no new pin can be born, so a pin
        // present here raced in after the unlocked pre-read — it carries no
        // refcount lock, so defer it to a fresh draining pass rather than let
        // the user delete cascade it away un-unpinned.
        if (await pinRepo.findOne({ where: { accountId } })) {
          return { kind: 'more' };
        }
        const namesRetired = (await nameRepo.delete({ accountId })).affected ?? 0;
        // Mailbox rows are keyed by recipient publicKey with no FK to users —
        // purge explicitly. Auth rows (auth_methods, refresh_tokens) cascade on
        // the users delete via their onDelete: 'CASCADE'.
        const mailboxPurged =
          (await mailboxRepo.delete({ recipientPublicKey: publicKey })).affected ?? 0;
        await manager.getRepository(User).delete({ id: accountId });
        return { kind: 'final', namesRetired, mailboxPurged };
      }

      const pinsRetired = (await pinRepo.delete({ accountId, cid: In(chunkCids) })).affected ?? 0;

      // Under the per-CID locks, a chunk CID with no surviving row across all
      // accounts is at global refcount zero. Co-registered shared content
      // survives via other accounts' rows (union liveness).
      const survivors = await pinRepo.find({ where: { cid: In(chunkCids) } });
      const surviving = new Set(survivors.map((row) => row.cid));
      return {
        kind: 'chunk',
        pinsRetired,
        unpinCids: chunkCids.filter((cid) => !surviving.has(cid)),
      };
    });
  }

  /**
   * Best-effort physical unpin after commit, each serialized on the upload
   * path's per-CID durability lock and gated on a survivor recount under it
   * (see class doc). Contention or a Kubo hiccup leaves the CID for GC. Returns
   * the count the seam confirms it released.
   */
  private async unpinAfterCommit(unpinCids: string[]): Promise<number> {
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
            if ((await this.pinRepository.find({ where: { cid } })).length > 0) {
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
    return unpinned;
  }
}
