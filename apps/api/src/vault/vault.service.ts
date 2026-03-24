import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { Vault } from './entities/vault.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { InitVaultDto, VaultResponseDto } from './dto/init-vault.dto';
import { VaultExportDto } from './dto/vault-export.dto';
import { QuotaResponseDto } from './dto/quota.dto';
import { VaultConfigResponseDto } from './dto/vault-config.dto';
import { TeeKeyStateService } from '../tee/tee-key-state.service';
import { TeeKeysDto } from '../tee/dto/tee-keys.dto';

/**
 * Storage quota limit: 500 MiB
 */
export const QUOTA_LIMIT_BYTES = 500 * 1024 * 1024; // 524,288,000 bytes

@Injectable()
export class VaultService {
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
    private readonly configService: ConfigService
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
    // Use upsert to avoid duplicate key constraint on (user_id, ipns_name).
    const existingFolderIpns = await this.folderIpnsRepository.findOne({
      where: { userId, ipnsName: dto.rootIpnsName },
    });

    if (existingFolderIpns) {
      // Mark as root if not already (publish endpoint creates with isRoot=false)
      if (!existingFolderIpns.isRoot) {
        existingFolderIpns.isRoot = true;
        await this.folderIpnsRepository.save(existingFolderIpns);
      }
    } else {
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
   * Get current storage quota usage for a user
   */
  async getQuota(userId: string): Promise<QuotaResponseDto> {
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
    };
  }

  /**
   * Check if user has sufficient quota for additional storage
   *
   * @returns true if (current usage + additionalBytes) <= quota limit
   */
  async checkQuota(userId: string, additionalBytes: number): Promise<boolean> {
    const quota = await this.getQuota(userId);
    return quota.usedBytes + additionalBytes <= QUOTA_LIMIT_BYTES;
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
   * Remove a pinned CID record
   * Idempotent - no error if CID not found
   */
  async recordUnpin(userId: string, cid: string): Promise<void> {
    await this.pinnedCidRepository.delete({
      userId,
      cid,
    });
  }

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
