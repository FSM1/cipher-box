import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, EntityManager, In, Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import {
  advisoryLockKey,
  boundedAcquire,
  pinDurabilityLockKey,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  withSessionAdvisoryLock,
} from '../../common/advisory-lock';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { byteConfigBigInt, DEFAULT_QUOTA_BYTES, resolveLimitBytes, sumPinnedBytes } from '../quota';

/**
 * Serialize every refcount/inventory mutation for each token by taking a
 * transaction-scoped advisory lock. Row locks can't see an unborn INSERT, so
 * only a per-token lock closes the register/retire phantom race and concurrent
 * duplicate inserts. Keys are acquired in sorted order so overlapping batches
 * cannot deadlock; the lock auto-releases at commit or rollback. One
 * `lock_timeout` bound covers the whole batch so a contended waiter aborts and
 * releases its pooled connection (surfacing as a 503) instead of holding it.
 */
async function lockTokens(
  manager: EntityManager,
  tokens: string[],
  timeoutMs: number
): Promise<void> {
  await boundedAcquire(manager, tokens.map(advisoryLockKey), timeoutMs);
}

export interface RegisterEntry {
  ipnsName: string;
  headCid?: string;
  contentCids: string[];
}

export interface RegisterResult {
  names: number;
  cids: number;
}

export interface RetireResult {
  retired: number;
  unpinned: number;
}

export interface QuotaResult {
  usedBytes: number;
  limitBytes: number;
  advisory: boolean;
}

/**
 * The pin/name registry (blueprint/api.md, Pin/name registry) — the one
 * surface every publish flow traverses. It is deliberately dumb bookkeeping:
 * per-account rows, idempotent upserts, union liveness, and a per-account
 * quota sum. It authorizes nothing across accounts and holds no state a
 * client cannot rebuild from the network.
 *
 * Determinism/side-effects are injected: the physical unpin rides the
 * [`PinStore`] seam, never a direct Kubo call in this logic.
 */
@Injectable()
export class RegistryService {
  private readonly defaultLimitBytes: bigint;
  private readonly lockTimeoutMs: number;
  private readonly logger = new Logger(RegistryService.name);

  constructor(
    @InjectRepository(PinnedCid)
    private readonly pinRepository: Repository<PinnedCid>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
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

  /**
   * Batch register `[{ipnsName, headCid?, contentCids[]}]` under the caller's
   * account. Register-first, fail-closed: each entry upserts its name-inventory
   * row BEFORE any content pin row, so content is never accepted without the
   * name that anchors it. Every upsert is idempotent — a replayed batch (name
   * waves re-reference the same CIDs) changes nothing.
   */
  async register(accountId: string, entries: RegisterEntry[]): Promise<RegisterResult> {
    // Collapse the batch to its distinct writes; the last-provided head wins
    // per name, matching the sequential upsert semantics.
    const heads = new Map<string, string | undefined>();
    const nameOrder: string[] = [];
    const cidOrder: string[] = [];
    const cids = new Set<string>();
    for (const entry of entries) {
      if (!heads.has(entry.ipnsName)) {
        nameOrder.push(entry.ipnsName);
        heads.set(entry.ipnsName, undefined);
      }
      if (entry.headCid !== undefined) {
        heads.set(entry.ipnsName, entry.headCid);
      }
      for (const cid of [...(entry.headCid ? [entry.headCid] : []), ...entry.contentCids]) {
        if (!cids.has(cid)) {
          cids.add(cid);
          cidOrder.push(cid);
        }
      }
    }

    // All-or-nothing: register-first, fail-closed means a mid-batch error must
    // leave no partial state behind.
    if (nameOrder.length > 0 || cidOrder.length > 0) {
      await runLockGuardedTransaction(this.dataSource, async (manager) => {
        // Serialize per token before any read/write: register and retire
        // contend on the same keys, closing the phantom-INSERT race and
        // concurrent-duplicate inserts.
        await lockTokens(manager, [...nameOrder, ...cidOrder], this.lockTimeoutMs);

        // Read BYO under a users-row lock: register and setByo contend on the
        // same existing row, so a row lock (not the token advisory lock) keeps
        // a concurrent toggle from stamping new pins with a stale advisory flag.
        const user = await manager.getRepository(User).findOne({
          where: { id: accountId },
          lock: { mode: 'pessimistic_write' },
        });
        if (!user) {
          throw new UnauthorizedException('Unknown account');
        }
        const advisory = user.byo;

        const nameRepo = manager.getRepository(NameInventory);
        const pinRepo = manager.getRepository(PinnedCid);

        // Names first: content is never accepted without its anchoring name.
        const existingNames = nameOrder.length
          ? await nameRepo.find({ where: { accountId, ipnsName: In(nameOrder) } })
          : [];
        const nameByKey = new Map(existingNames.map((row) => [row.ipnsName, row]));
        const nameWrites: Partial<NameInventory>[] = [];
        for (const ipnsName of nameOrder) {
          const head = heads.get(ipnsName);
          const existing = nameByKey.get(ipnsName);
          if (existing) {
            // A bare re-register (no head) leaves the head untouched.
            if (head !== undefined && existing.headCid !== head) {
              existing.headCid = head;
              nameWrites.push(existing);
            }
          } else {
            nameWrites.push({ accountId, ipnsName, headCid: head ?? null });
          }
        }
        if (nameWrites.length) {
          await nameRepo.save(nameWrites);
        }

        const existingPins = cidOrder.length
          ? await pinRepo.find({ where: { accountId, cid: In(cidOrder) } })
          : [];
        const knownCids = new Set(existingPins.map((row) => row.cid));
        // Idempotent: a CID already counted keeps its size and advisory origin.
        // All-new rows, so one multi-row INSERT instead of per-row saves.
        const pinWrites = cidOrder
          .filter((cid) => !knownCids.has(cid))
          .map((cid) => ({ accountId, cid, size: '0', advisory }));
        if (pinWrites.length) {
          await pinRepo.insert(pinWrites);
        }
      });
    }

    // `names` is the distinct-name count (the DTO contract), not the raw batch
    // length, which double-counts a name repeated across entries.
    return { names: nameOrder.length, cids: cids.size };
  }

  /**
   * Batch retire `[ipnsName | cid]` for the caller's account. A target may be
   * either a name or a CID; the API is zero-knowledge about which, so it
   * removes the caller's matching row from BOTH tables (their namespaces do
   * not collide). Union liveness: a retired CID is physically unpinned only
   * when the LAST account's row for it is gone (global refcount zero).
   */
  async retire(accountId: string, targets: string[]): Promise<RetireResult> {
    if (targets.length === 0) {
      return { retired: 0, unpinned: 0 };
    }

    // All-or-nothing, and serialized per CID against concurrent register and
    // retire: the advisory lock (not a row lock, which can't see an unborn
    // INSERT) makes the delete → survivor check the authority for unpinning.
    const { retired, unpinCids } = await runLockGuardedTransaction(
      this.dataSource,
      async (manager) => {
        await lockTokens(manager, targets, this.lockTimeoutMs);

        const nameRepo = manager.getRepository(NameInventory);
        const pinRepo = manager.getRepository(PinnedCid);

        const held = await pinRepo.find({ where: { accountId, cid: In(targets) } });
        const heldByCaller = new Set(held.map((row) => row.cid));
        const heldCids = [...new Set(targets)].filter((target) => heldByCaller.has(target));

        const nameDeleted = await nameRepo.delete({ accountId, ipnsName: In(targets) });
        const pinDeleted = await pinRepo.delete({ accountId, cid: In(targets) });

        // Under the lock, a held CID with no surviving row is at global zero.
        const survivors = heldCids.length
          ? await pinRepo.find({ where: { cid: In(heldCids) } })
          : [];
        const surviving = new Set(survivors.map((row) => row.cid));

        return {
          retired: (nameDeleted.affected ?? 0) + (pinDeleted.affected ?? 0),
          unpinCids: heldCids.filter((cid) => !surviving.has(cid)),
        };
      }
    );

    // Fire the external unpin after commit — never hold the txn across Kubo.
    // The retire txn's per-token xact lock releases at commit, so between it and
    // this unpin a concurrent upload can re-pin the same CID under the upload
    // path's `pin-durability:` session lock, commit a row, and return success —
    // an unguarded unpin here would then delete freshly-pinned, durably-held
    // bytes (#714). Re-serialize on that SAME session key and recount under it:
    // if a survivor row now exists the bytes are legitimately held, so skip.
    //
    // The destructive work — the row deletes — is already committed, so `retired`
    // is authoritative and must stay observable. unpin is best-effort (PinStore
    // contract: a failed unpin never fails a retire; the CID decays via GC), so a
    // per-CID durability lock that is contended here — almost always a concurrent
    // upload re-pinning that same CID — leaves the CID pinned and moves on,
    // rather than discarding the committed result behind a misleading 503 (#723).
    let unpinned = 0;
    for (const cid of unpinCids) {
      try {
        const didUnpin = await withSessionAdvisoryLock(
          this.dataSource,
          pinDurabilityLockKey(cid),
          this.lockTimeoutMs,
          async () => {
            const survivors = await this.pinRepository.find({ where: { cid } });
            if (survivors.length > 0) {
              return false;
            }
            // Count only seam-confirmed releases; a no-op/swallowed unpin (Kubo
            // hiccup, unconfigured store) returns false and must not be counted.
            return this.pinStore.unpin(cid);
          }
        );
        if (didUnpin) {
          unpinned += 1;
        }
      } catch (error) {
        // The row deletes already committed and `retired` is authoritative; the
        // post-commit unpin is best-effort (PinStore contract), so no failure
        // here — lock contention or otherwise — may turn a retire into a 500.
        this.logger.warn(`retire left ${cid} pinned for GC: ${String(error)}`);
      }
    }

    return { retired, unpinned };
  }

  /**
   * The per-account quota (blueprint/api.md). `usedBytes` is the sum over the
   * account's pin rows; `limitBytes` is the per-account override, else the env
   * default. Hosted accounts are authoritative (`advisory: false`, the sum
   * gates uploads); a BYO account's rows are advisory (`advisory: true`, quota
   * always allows) — the bytes live on the user's own provider.
   */
  async quota(accountId: string): Promise<QuotaResult> {
    const user = await this.userRepository.findOne({ where: { id: accountId } });
    if (!user) {
      throw new UnauthorizedException('Unknown account');
    }

    // Compute in BigInt (exact above 2^53) and narrow to the wire number at the
    // edge; the DTO is a JSON number, but the gate math never rounds (#677).
    const used = await sumPinnedBytes(this.pinRepository, accountId);
    const limit = resolveLimitBytes(user.quotaLimitOverride, this.defaultLimitBytes);

    return {
      usedBytes: Number(used),
      limitBytes: Number(limit),
      advisory: user.byo,
    };
  }

  /** Toggle the account's BYO flag; new pin rows are advisory while set. */
  async setByo(accountId: string, byo: boolean): Promise<{ byo: boolean }> {
    const result = await this.userRepository.update({ id: accountId }, { byo });
    if (!result.affected) {
      throw new UnauthorizedException('Unknown account');
    }
    return { byo };
  }
}
