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
import { PinReference } from '../entities/pin-reference.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { byteConfigBigInt, DEFAULT_QUOTA_BYTES, quotaSums, resolveLimitBytes } from '../quota';

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

/**
 * Postgres binds at most 65535 parameters per statement, so a bulk write is
 * sliced rather than issued whole: a max batch would otherwise fail outright
 * once its row count crossed the bind ceiling.
 */
const BIND_CHUNK_ROWS = 5000;

function chunked<T>(rows: T[]): T[][] {
  const slices: T[][] = [];
  for (let start = 0; start < rows.length; start += BIND_CHUNK_ROWS) {
    slices.push(rows.slice(start, start + BIND_CHUNK_ROWS));
  }
  return slices;
}

export interface RegisterEntry {
  ipnsName: string;
  headCid?: string;
  contentCids: string[];
}

/** One retire entry; see [`RegistryService.retire`] for the two forms. */
export interface RetireEntry {
  ipnsName?: string;
  targets: string[];
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
  pinnedBytes: number;
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
    const referenced = new Map<string, Set<string>>();
    for (const entry of entries) {
      if (!heads.has(entry.ipnsName)) {
        nameOrder.push(entry.ipnsName);
        heads.set(entry.ipnsName, undefined);
        referenced.set(entry.ipnsName, new Set());
      }
      if (entry.headCid !== undefined) {
        heads.set(entry.ipnsName, entry.headCid);
      }
      for (const cid of [...(entry.headCid ? [entry.headCid] : []), ...entry.contentCids]) {
        if (!cids.has(cid)) {
          cids.add(cid);
          cidOrder.push(cid);
        }
        referenced.get(entry.ipnsName)?.add(cid);
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

        // Claim this batch's reference edges. The unique index carries the
        // idempotency, so a replay re-claims the same edges and changes nothing.
        const refRepo = manager.getRepository(PinReference);
        const edges = [...referenced].flatMap(([ipnsName, named]) =>
          [...named].map((cid) => ({ accountId, ipnsName, cid }))
        );
        for (const slice of chunked(edges)) {
          await refRepo
            .createQueryBuilder()
            .insert()
            .into(PinReference)
            .values(slice)
            .orIgnore()
            .execute();
        }

        const existingPins = cidOrder.length
          ? await pinRepo.find({ where: { accountId, cid: In(cidOrder) } })
          : [];
        const knownCids = new Set(existingPins.map((row) => row.cid));
        // Idempotent: a CID already counted keeps its size and advisory origin;
        // the rest are all-new, so one multi-row insert.
        const pinWrites = cidOrder
          .filter((cid) => !knownCids.has(cid))
          .map((cid) => ({ accountId, cid, size: '0', advisory }));
        for (const slice of chunked(pinWrites)) {
          await pinRepo.insert(slice);
        }
      });
    }

    // `names` is the distinct-name count (the DTO contract), not the raw batch
    // length, which double-counts a name repeated across entries.
    return { names: nameOrder.length, cids: cids.size };
  }

  /**
   * Batch retire `[{ipnsName?, targets[]}]` for the caller's account. A target
   * may be either a name or a CID; the API is zero-knowledge about which, so it
   * removes the caller's matching row from BOTH tables (their namespaces do not
   * collide).
   *
   * An entry's `ipnsName` scopes the drop to that record's reference edges
   * ([`PinReference`]); an entry with no `ipnsName` drops every record's edge
   * and is the only form whose targets may name a record. Union liveness across
   * accounts is unchanged: a CID is physically unpinned only when the LAST
   * account's pin row for it is gone (global refcount zero).
   */
  async retire(accountId: string, entries: RetireEntry[]): Promise<RetireResult> {
    const targets = [...new Set(entries.flatMap((entry) => entry.targets))];
    if (targets.length === 0) {
      return { retired: 0, unpinned: 0 };
    }

    // One target set per record scope; an entry with no scope folds into the
    // account-wide set.
    const scoped = new Map<string, Set<string>>();
    const unscoped = new Set<string>();
    for (const entry of entries) {
      let into = unscoped;
      if (entry.ipnsName !== undefined) {
        into = scoped.get(entry.ipnsName) ?? new Set();
        scoped.set(entry.ipnsName, into);
      }
      for (const target of entry.targets) {
        into.add(target);
      }
    }

    // All-or-nothing, and serialized per CID and per record scope against
    // concurrent register and retire: the advisory lock (not a row lock, which
    // can't see an unborn INSERT) makes the delete → survivor check the
    // authority for unpinning.
    const { retired, unpinCids } = await runLockGuardedTransaction(
      this.dataSource,
      async (manager) => {
        await lockTokens(manager, [...new Set([...targets, ...scoped.keys()])], this.lockTimeoutMs);

        const nameRepo = manager.getRepository(NameInventory);
        const pinRepo = manager.getRepository(PinnedCid);
        const refRepo = manager.getRepository(PinReference);

        const held = await pinRepo.find({ where: { accountId, cid: In(targets) } });
        const heldCids = held.map((row) => row.cid);

        // Only an unscoped target may name a record: a scoped entry says the
        // record stops referencing CIDs, never that the record itself is dead.
        const retiredNames = [...unscoped];
        const nameDeleted = retiredNames.length
          ? await nameRepo.delete({ accountId, ipnsName: In(retiredNames) })
          : { affected: 0 };

        // Every edge this batch can touch: the ones a retired name anchored,
        // and the ones that name a target CID. Read once, so the batch costs a
        // fixed number of statements however its entries are split.
        const anchored = retiredNames.length
          ? await refRepo.find({ where: { accountId, ipnsName: In(retiredNames) } })
          : [];
        const naming = await refRepo.find({ where: { accountId, cid: In(targets) } });
        const doomed = new Set(anchored.map((row) => row.id));
        for (const edge of naming) {
          if (unscoped.has(edge.cid) || scoped.get(edge.ipnsName)?.has(edge.cid)) {
            doomed.add(edge.id);
          }
        }
        for (const slice of chunked([...doomed])) {
          await refRepo.delete({ id: In(slice) });
        }

        // A pin row goes only once no record of the account names it any more.
        const stillNamed = new Set(
          naming.filter((edge) => !doomed.has(edge.id)).map((edge) => edge.cid)
        );
        const dropCids = heldCids.filter((cid) => !stillNamed.has(cid));
        const pinDeleted = dropCids.length
          ? await pinRepo.delete({ accountId, cid: In(dropCids) })
          : { affected: 0 };

        // Under the lock, a dropped CID with no surviving row is at global zero.
        const survivors = dropCids.length
          ? await pinRepo.find({ where: { cid: In(dropCids) } })
          : [];
        const surviving = new Set(survivors.map((row) => row.cid));

        return {
          retired: (nameDeleted.affected ?? 0) + (pinDeleted.affected ?? 0),
          unpinCids: dropCids.filter((cid) => !surviving.has(cid)),
        };
      }
    );

    // Fire the external unpin after commit — never hold the txn across Kubo.
    // The retire txn's per-token xact lock releases at commit, so between it and
    // this unpin a concurrent upload can re-pin the same CID under the upload
    // path's `pin-durability:` session lock, commit a row, and return success —
    // an unguarded unpin here would then delete freshly-pinned, durably-held
    // bytes. Re-serialize on that SAME session key and recount under it:
    // if a survivor row now exists the bytes are legitimately held, so skip.
    //
    // The destructive work — the row deletes — is already committed, so `retired`
    // is authoritative and must stay observable. unpin is best-effort (PinStore
    // contract: a failed unpin never fails a retire; the CID decays via GC), so a
    // per-CID durability lock that is contended here — almost always a concurrent
    // upload re-pinning that same CID — leaves the CID pinned and moves on,
    // rather than discarding the committed result behind a misleading 503.
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
   * The per-account quota (blueprint/api.md). `usedBytes` is the GATED sum the
   * upload gate itself enforces, so a client pre-flight and a server refusal
   * read one number by construction; `pinnedBytes` is the all-rows sum,
   * informational only. `limitBytes` is the per-account override, else the env
   * default. A BYO account's rows are advisory (`advisory: true`, quota always
   * allows) — the bytes live on the user's own provider.
   */
  async quota(accountId: string): Promise<QuotaResult> {
    const user = await this.userRepository.findOne({ where: { id: accountId } });
    if (!user) {
      throw new UnauthorizedException('Unknown account');
    }

    // Compute in BigInt (exact above 2^53) and narrow to the wire number at the
    // edge; the DTO is a JSON number, but the gate math never rounds.
    const sums = await quotaSums(this.pinRepository, accountId);
    const limit = resolveLimitBytes(user.quotaLimitOverride, this.defaultLimitBytes);

    return {
      usedBytes: Number(sums.hosted),
      pinnedBytes: Number(sums.pinned),
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
