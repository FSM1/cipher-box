import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';

/** Default per-account quota when neither an override nor `QUOTA_DEFAULT_BYTES` is set: 10 GiB. */
const DEFAULT_QUOTA_BYTES = 10 * 1024 * 1024 * 1024;

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
    @InjectRepository(NameInventory)
    private readonly nameRepository: Repository<NameInventory>,
    @InjectRepository(PinnedCid)
    private readonly pinRepository: Repository<PinnedCid>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
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
    const cids = new Set<string>();

    for (const entry of entries) {
      // Register-first: the name row exists before its content is accepted.
      await this.upsertName(accountId, entry.ipnsName, entry.headCid);

      const entryCids = [...(entry.headCid ? [entry.headCid] : []), ...entry.contentCids];
      for (const cid of entryCids) {
        await this.upsertPin(accountId, cid, advisory);
        cids.add(cid);
      }
    }

    return { names: entries.length, cids: cids.size };
  }

  /**
   * Batch retire `[ipnsName | cid]` for the caller's account. A target may be
   * either a name or a CID; the API is zero-knowledge about which, so it
   * removes the caller's matching row from BOTH tables (their namespaces do
   * not collide). Union liveness: a retired CID is physically unpinned only
   * when the LAST account's row for it is gone (global refcount zero).
   */
  async retire(accountId: string, targets: string[]): Promise<RetireResult> {
    let retired = 0;
    let unpinned = 0;

    for (const target of targets) {
      const nameDeleted = await this.nameRepository.delete({ accountId, ipnsName: target });
      retired += nameDeleted.affected ?? 0;

      const pinDeleted = await this.pinRepository.delete({ accountId, cid: target });
      const pinAffected = pinDeleted.affected ?? 0;
      retired += pinAffected;

      // Only the account that actually held this CID can drop the global
      // refcount; check it exactly when a row was removed.
      if (pinAffected > 0) {
        const remaining = await this.pinRepository.count({ where: { cid: target } });
        if (remaining === 0) {
          await this.pinStore.unpin(target);
          unpinned += 1;
        }
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

    const rows = await this.pinRepository.find({ where: { accountId } });
    let used = 0n;
    for (const row of rows) {
      used += BigInt(row.size ?? '0');
    }

    const limitBytes =
      user.quotaLimitOverride != null
        ? Number(BigInt(user.quotaLimitOverride))
        : this.defaultLimitBytes;

    return {
      usedBytes: Number(used),
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

  private async upsertName(accountId: string, ipnsName: string, headCid?: string): Promise<void> {
    const existing = await this.nameRepository.findOne({ where: { accountId, ipnsName } });
    if (existing) {
      // Idempotent: a re-publish only advances the head; a bare re-register
      // (no headCid) leaves the existing head untouched.
      if (headCid !== undefined && existing.headCid !== headCid) {
        existing.headCid = headCid;
        await this.nameRepository.save(existing);
      }
      return;
    }
    await this.nameRepository.save({ accountId, ipnsName, headCid: headCid ?? null });
  }

  private async upsertPin(accountId: string, cid: string, advisory: boolean): Promise<void> {
    const existing = await this.pinRepository.findOne({ where: { accountId, cid } });
    if (existing) {
      // Idempotent: the CID is already counted; its size (set by the hosted
      // upload path) and advisory origin are preserved.
      return;
    }
    await this.pinRepository.save({ accountId, cid, size: '0', advisory });
  }
}
