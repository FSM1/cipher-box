import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'node:crypto';
import { DataSource, EntityManager, In, Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';

/** Default per-account quota when neither an override nor `QUOTA_DEFAULT_BYTES` is set: 10 GiB. */
const DEFAULT_QUOTA_BYTES = 10 * 1024 * 1024 * 1024;

/** Stable 64-bit advisory-lock key for a token: first 8 bytes of its sha256. */
function lockKey(token: string): bigint {
  return createHash('sha256').update(token).digest().readBigInt64BE(0);
}

/**
 * Serialize every refcount/inventory mutation for each token by taking a
 * transaction-scoped advisory lock. Row locks can't see an unborn INSERT, so
 * only a per-token lock closes the register/retire phantom race and concurrent
 * duplicate inserts. Keys are acquired in sorted order so overlapping batches
 * cannot deadlock; the lock auto-releases at commit or rollback.
 */
async function lockTokens(manager: EntityManager, tokens: string[]): Promise<void> {
  const keys = [...new Set(tokens.map(lockKey))].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (const key of keys) {
    await manager.query('SELECT pg_advisory_xact_lock($1::bigint)', [key.toString()]);
  }
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
 * Read a non-negative integer byte bound from config, falling back to the
 * default for an unset OR garbage value (a misconfigured limit must fail
 * closed to the safe default, never to NaN).
 */
function byteConfig(raw: unknown, fallback: number): number {
  const value = Number(raw);
  return Number.isInteger(value) && value >= 0 ? value : fallback;
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
  private readonly defaultLimitBytes: number;

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
    this.defaultLimitBytes = byteConfig(
      configService.get('QUOTA_DEFAULT_BYTES'),
      DEFAULT_QUOTA_BYTES
    );
  }

  /**
   * Batch register `[{ipnsName, headCid?, contentCids[]}]` under the caller's
   * account. Register-first, fail-closed: each entry upserts its name-inventory
   * row BEFORE any content pin row, so content is never accepted without the
   * name that anchors it. Every upsert is idempotent — a replayed batch (name
   * waves re-reference the same CIDs) changes nothing.
   */
  async register(accountId: string, entries: RegisterEntry[]): Promise<RegisterResult> {
    const advisory = await this.isByo(accountId);

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
      await this.dataSource.transaction(async (manager) => {
        // Serialize per token before any read/write: register and retire
        // contend on the same keys, closing the phantom-INSERT race and
        // concurrent-duplicate inserts.
        await lockTokens(manager, [...nameOrder, ...cidOrder]);

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
        const pinWrites = cidOrder
          .filter((cid) => !knownCids.has(cid))
          .map((cid) => ({ accountId, cid, size: '0', advisory }));
        if (pinWrites.length) {
          await pinRepo.save(pinWrites);
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
    const { retired, unpinCids } = await this.dataSource.transaction(async (manager) => {
      await lockTokens(manager, targets);

      const nameRepo = manager.getRepository(NameInventory);
      const pinRepo = manager.getRepository(PinnedCid);

      const held = await pinRepo.find({ where: { accountId, cid: In(targets) } });
      const heldByCaller = new Set(held.map((row) => row.cid));
      const heldCids = targets.filter(
        (target, index) => targets.indexOf(target) === index && heldByCaller.has(target)
      );

      const nameDeleted = await nameRepo.delete({ accountId, ipnsName: In(targets) });
      const pinDeleted = await pinRepo.delete({ accountId, cid: In(targets) });

      // Under the lock, a held CID with no surviving row is at global zero.
      const survivors = heldCids.length ? await pinRepo.find({ where: { cid: In(heldCids) } }) : [];
      const surviving = new Set(survivors.map((row) => row.cid));

      return {
        retired: (nameDeleted.affected ?? 0) + (pinDeleted.affected ?? 0),
        unpinCids: heldCids.filter((cid) => !surviving.has(cid)),
      };
    });

    // Fire the external unpin after commit — never hold the txn across Kubo.
    let unpinned = 0;
    for (const cid of unpinCids) {
      await this.pinStore.unpin(cid);
      unpinned += 1;
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

    // Aggregate server-side; size is a bigint column typed as string.
    const used = await this.pinRepository.sum('size' as never, { accountId });

    const limitBytes =
      user.quotaLimitOverride != null
        ? Number(BigInt(user.quotaLimitOverride))
        : this.defaultLimitBytes;

    return {
      usedBytes: used ?? 0,
      limitBytes,
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

  private async isByo(accountId: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: accountId } });
    if (!user) {
      throw new UnauthorizedException('Unknown account');
    }
    return user.byo;
  }
}
