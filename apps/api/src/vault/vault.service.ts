import { Injectable, ConflictException, NotFoundException, Inject, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { DataSource, Repository } from 'typeorm';
import { Vault } from './entities/vault.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { PendingUnpin } from './entities/pending-unpin.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { InitVaultDto, VaultResponseDto } from './dto/init-vault.dto';
import { VaultExportDto } from './dto/vault-export.dto';
import { QuotaResponseDto } from './dto/quota.dto';
import { VaultConfigResponseDto } from './dto/vault-config.dto';
import { TeeKeyStateService } from '../tee/tee-key-state.service';
import { TeeKeysDto } from '../tee/dto/tee-keys.dto';
import { IPFS_PROVIDER, IpfsProvider } from '../ipfs/providers';
import { withCidLock } from '../ipfs/pending-unpin/unpin-helpers';
import { MetricsService } from '../metrics/metrics.service';

/**
 * Storage quota limit: 500 MiB
 */
export const QUOTA_LIMIT_BYTES = 500 * 1024 * 1024; // 524,288,000 bytes

@Injectable()
export class VaultService {
  private readonly logger = new Logger(VaultService.name);

  constructor(
    @InjectRepository(Vault)
    private readonly vaultRepository: Repository<Vault>,
    @InjectRepository(PinnedCid)
    private readonly pinnedCidRepository: Repository<PinnedCid>,
    @InjectRepository(FolderIpns)
    private readonly folderIpnsRepository: Repository<FolderIpns>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly teeKeyStateService: TeeKeyStateService,
    private readonly configService: ConfigService,
    private readonly dataSource: DataSource,
    @Inject(IPFS_PROVIDER)
    private readonly ipfsProvider: IpfsProvider,
    private readonly metricsService: MetricsService
  ) {}

  /**
   * Get application configuration including recycle bin retention period.
   */
  getConfig(): VaultConfigResponseDto {
    const raw = this.configService.get<string>('RECYCLE_BIN_RETENTION_DAYS');
    let retentionDays = Number(raw);
    if (!Number.isFinite(retentionDays) || retentionDays < 0) {
      retentionDays = 30;
    }
    return {
      recycleBinRetentionDays: retentionDays,
    };
  }

  /**
   * Initialize a new vault for a user
   * Creates the vault with encrypted keys on first sign-in
   *
   * @throws ConflictException if vault already exists for user
   */
  async initializeVault(userId: string, dto: InitVaultDto): Promise<VaultResponseDto> {
    // Check if vault already exists
    const existingVault = await this.vaultRepository.findOne({
      where: { ownerId: userId },
    });

    if (existingVault) {
      throw new ConflictException('Vault already exists for this user');
    }

    // Decode hex strings to buffers
    const vault = this.vaultRepository.create({
      ownerId: userId,
      ownerPublicKey: Buffer.from(dto.ownerPublicKey, 'hex'),
      rootIpnsName: dto.rootIpnsName,
      initializedAt: null,
    });

    const savedVault = await this.vaultRepository.save(vault);

    // Ensure root folder IPNS entry exists for publish tracking.
    // The IPNS publish endpoint may have already created this row (clients
    // publish the root folder IPNS record before calling /vault/init).
    // Try insert first; on duplicate key, update isRoot instead.
    try {
      const rootFolderIpns = this.folderIpnsRepository.create({
        userId,
        ipnsName: dto.rootIpnsName,
        latestCid: null,
        sequenceNumber: '0',
        encryptedIpnsPrivateKey: null,
        keyEpoch: null,
        isRoot: true,
      });
      await this.folderIpnsRepository.save(rootFolderIpns);
    } catch (error) {
      // Row already exists (from IPNS publish endpoint) — mark as root
      if ((error as { code?: string }).code === '23505') {
        await this.folderIpnsRepository.update(
          { userId, ipnsName: dto.rootIpnsName },
          { isRoot: true }
        );
      } else {
        throw error;
      }
    }

    const teeKeys = await this.teeKeyStateService.getTeeKeysDto();
    return this.toVaultResponse(savedVault, teeKeys);
  }

  /**
   * Get vault for a user
   *
   * @throws NotFoundException if vault does not exist
   */
  async getVault(userId: string): Promise<VaultResponseDto> {
    const vault = await this.vaultRepository.findOne({
      where: { ownerId: userId },
    });

    if (!vault) {
      throw new NotFoundException('Vault not found');
    }

    const teeKeys = await this.teeKeyStateService.getTeeKeysDto();
    return this.toVaultResponse(vault, teeKeys);
  }

  /**
   * Check if vault exists for user (returns null if not)
   */
  async findVault(userId: string): Promise<VaultResponseDto | null> {
    const vault = await this.vaultRepository.findOne({
      where: { ownerId: userId },
    });

    if (!vault) return null;

    const teeKeys = await this.teeKeyStateService.getTeeKeysDto();
    return this.toVaultResponse(vault, teeKeys);
  }

  /**
   * Check if user is in BYO (Bring Your Own) IPFS mode.
   * BYO users manage their own IPFS node; quota is advisory only.
   */
  async isUserByo(userId: string): Promise<boolean> {
    const vault = await this.vaultRepository.findOne({
      where: { ownerId: userId },
      select: ['isByoUser'],
    });
    return vault?.isByoUser ?? false;
  }

  /**
   * Set BYO status for a user's vault.
   */
  async setByoStatus(userId: string, isByo: boolean): Promise<void> {
    await this.vaultRepository.update({ ownerId: userId }, { isByoUser: isByo });
  }

  /**
   * Get current storage quota usage for a user.
   * For BYO users, the advisory flag is set to true.
   */
  async getQuota(userId: string): Promise<QuotaResponseDto> {
    const isByo = await this.isUserByo(userId);

    const result = await this.pinnedCidRepository
      .createQueryBuilder('pin')
      .select('COALESCE(SUM(pin.size_bytes), 0)', 'total')
      .where('pin.user_id = :userId', { userId })
      .getRawOne<{ total: string }>();

    const usedBytes = parseInt(result?.total ?? '0', 10);
    const remainingBytes = Math.max(0, QUOTA_LIMIT_BYTES - usedBytes);

    return {
      usedBytes,
      limitBytes: QUOTA_LIMIT_BYTES,
      remainingBytes,
      advisory: isByo,
    };
  }

  /**
   * Check if user has sufficient quota for additional storage.
   * BYO users always pass (advisory only -- no enforcement).
   *
   * @returns true if BYO user OR (current usage + additionalBytes) <= quota limit
   */
  async checkQuota(userId: string, additionalBytes: number): Promise<boolean> {
    const isByo = await this.isUserByo(userId);
    if (isByo) return true; // Advisory only -- always allow

    // Query usage directly to avoid redundant isUserByo call in getQuota
    const result = await this.pinnedCidRepository
      .createQueryBuilder('pin')
      .select('COALESCE(SUM(pin.size_bytes), 0)', 'total')
      .where('pin.user_id = :userId', { userId })
      .getRawOne<{ total: string }>();

    const usedBytes = parseInt(result?.total ?? '0', 10);
    return usedBytes + additionalBytes <= QUOTA_LIMIT_BYTES;
  }

  /**
   * Record a pinned CID for quota tracking
   * Uses upsert (ON CONFLICT DO NOTHING) for idempotency
   */
  async recordPin(userId: string, cid: string, sizeBytes: number): Promise<void> {
    await this.pinnedCidRepository
      .createQueryBuilder()
      .insert()
      .into(PinnedCid)
      .values({
        userId,
        cid,
        sizeBytes: sizeBytes.toString(),
      })
      .orIgnore() // ON CONFLICT DO NOTHING for idempotency
      .execute();
  }

  /**
   * Guarded unpin: enforces ownership, serializes with per-CID advisory lock,
   * decrements quota by deleting the caller's pinned_cids row inside a transaction,
   * reference-counts across all users and only queues a physical unpin via the
   * pending_unpins outbox when the count hits zero, emits cross-user audit telemetry,
   * and best-effort attempts the inline Kubo pin/rm after commit.
   *
   * Security properties (D-01..D-05):
   * - D-01: Ownership check; no-row path touches nothing (no oracle)
   * - D-02: Cross-user attempt increments unpinCrossUserAttempts metric + warns
   *         (skipped when options.suppressCrossUserAudit is set — used by internal
   *         upload-rollback compensation, which is not an external probe)
   * - D-03: Row delete IS the quota decrement (in-transaction); Kubo outside
   * - D-04: pg_advisory_xact_lock as first statement serializes concurrent deletes
   * - D-05: orIgnore insert into outbox only when refcount === 0
   */
  async guardedUnpin(
    userId: string,
    cid: string,
    options?: { suppressCrossUserAudit?: boolean }
  ): Promise<void> {
    // IN-06: renamed from `outboxRowInserted` (misleading — the flag also gates the
    // post-commit Kubo call, which has nothing to do with an "outbox row insertion").
    // The new name describes the flag's actual semantics.
    let shouldAttemptPhysicalUnpin = false;
    // IN-01: track whether a pinned_cids row was actually deleted so the metric only
    // fires on real unpins, not on no-op paths (unknown CID, cross-user, refcount > 0).
    let rowDeleted = false;

    await this.dataSource.transaction(async (manager) => {
      const pinnedCidRepo = manager.getRepository(PinnedCid);
      const pendingUnpinRepo = manager.getRepository(PendingUnpin);

      // 1. Advisory xact lock — MUST be the first transactional statement (D-04).
      // Lock is acquired via withCidLock (unpin-helpers.ts) which runs the verbatim
      // INT_MIN-safe SQL: pg_advisory_xact_lock(hashtext($1)::bigint) with NO abs().
      await withCidLock(manager, cid, async () => {
        // 2. Ownership check (D-01)
        const row = await pinnedCidRepo.findOne({ where: { userId, cid } });
        if (!row) {
          const otherRow = await pinnedCidRepo.findOne({ where: { cid } });
          if (otherRow && !options?.suppressCrossUserAudit) {
            this.logger.warn(`Cross-user unpin attempt userId=${userId} cid=${cid}`);
            this.metricsService.unpinCrossUserAttempts.inc();
          }
          return; // silent 2XX (D-01: no oracle — same response for unknown vs cross-user)
        }

        // 3. Delete caller's row — this IS the quota decrement (D-03)
        const deleteResult = await pinnedCidRepo.delete({ userId, cid });
        rowDeleted = (deleteResult.affected ?? 0) > 0; // IN-01: only true on an actual row deletion

        // 4. Refcount across all users (D-05, D-07: no origin filtering)
        // WR-07 disposition: BYO advisory rows intentionally count toward the hosted
        // refcount — this is the D-07 design: a BYO advisory row blocks physical unpin
        // of hosted content until that BYO row is removed. See docs/CAPACITY.md §7 for
        // the retention consequence. (WR-07 accepted: filtering BYO rows would change
        // refcount semantics and break the shared-owner-vs-BYO invariant from D-07.)
        const result = await manager
          .createQueryBuilder(PinnedCid, 'pc')
          .select('COUNT(*)', 'count')
          .where('pc.cid = :cid', { cid })
          .getRawOne<{ count: string }>();
        const refcount = parseInt(result?.count ?? '0', 10);

        if (refcount === 0) {
          // 5. Queue physical unpin via outbox — orIgnore dedupes concurrent inserts (Pitfall 5)
          await pendingUnpinRepo
            .createQueryBuilder()
            .insert()
            .into(PendingUnpin)
            .values({ cid })
            .orIgnore()
            .execute();
          shouldAttemptPhysicalUnpin = true; // IN-06: flag gates the post-commit Kubo call
        }
        // Transaction commits; advisory lock released automatically at end of transaction
      });
    });

    // 6. Post-commit best-effort Kubo call (D-03 ordering: NEVER inside transaction, Pitfall 3)
    if (shouldAttemptPhysicalUnpin) {
      try {
        await this.ipfsProvider.unpinFile(cid);
        // WR-03: serialize the outbox-row delete with the per-CID refcount decision by
        // re-taking the same advisory lock used above before deleting. Without the lock,
        // this delete races a concurrent guardedUnpin/drain that re-inserted the outbox
        // row as its retry safety net, and could remove the row out from under it. The
        // Kubo call stays outside the lock/transaction (D-03 ordering, Pitfall 3); only
        // the row delete is serialized.
        await this.dataSource.transaction(async (manager) => {
          // Post-commit: Kubo call already ran outside this transaction (D-03 ordering).
          // Only the outbox-row delete is serialized under the advisory lock.
          await withCidLock(manager, cid, async () => {
            await manager.getRepository(PendingUnpin).delete({ cid });
          });
        });
      } catch {
        // Leave outbox row for BullMQ retry worker — Kubo failure is not a request failure
      }
    }

    // IN-01: increment fileUnpins only when a pinned_cids row was actually deleted.
    // Prior to this fix the metric fired unconditionally, inflating counts on no-op
    // paths (unknown CID, cross-user attempt, early returns above).
    if (rowDeleted) {
      this.metricsService.fileUnpins.inc();
    }
  }

  // IN-03: recordUnpin removed — it had zero production callers and its only
  // reference was its own test. All production unpin paths go through guardedUnpin,
  // which handles ownership checks, refcounting, and outbox-based physical unpin.
  // (Deleted rather than @deprecated because there is no caller to migrate.)

  /**
   * Mark vault as initialized (first file uploaded)
   */
  async markInitialized(userId: string): Promise<void> {
    await this.vaultRepository.update({ ownerId: userId }, { initializedAt: new Date() });
  }

  /**
   * Get export data for independent recovery.
   * Returns the minimal set of fields needed to reconstruct the vault:
   * root IPNS name + encrypted root keys + derivation hints.
   */
  async getExportData(userId: string): Promise<VaultExportDto> {
    const vault = await this.vaultRepository.findOne({
      where: { ownerId: userId },
    });

    if (!vault) {
      throw new NotFoundException('Vault not found');
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    return {
      format: 'cipherbox-vault-export',
      version: '1.0',
      exportedAt: new Date().toISOString(),
      rootIpnsName: vault.rootIpnsName,
      derivationMethod: user ? 'web3auth' : null,
    };
  }

  /**
   * Convert Vault entity to response DTO with hex-encoded fields
   */
  private toVaultResponse(vault: Vault, teeKeys: TeeKeysDto | null = null): VaultResponseDto {
    return {
      id: vault.id,
      ownerPublicKey: vault.ownerPublicKey.toString('hex'),
      rootIpnsName: vault.rootIpnsName,
      createdAt: vault.createdAt,
      initializedAt: vault.initializedAt,
      teeKeys,
    };
  }
}
