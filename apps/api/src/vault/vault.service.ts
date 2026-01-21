import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Vault } from './entities/vault.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { InitVaultDto, VaultResponseDto } from './dto/init-vault.dto';
import { QuotaResponseDto } from './dto/quota.dto';

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
    private readonly pinnedCidRepository: Repository<PinnedCid>
  ) {}

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
      encryptedRootFolderKey: Buffer.from(dto.encryptedRootFolderKey, 'hex'),
      encryptedRootIpnsPrivateKey: Buffer.from(dto.encryptedRootIpnsPrivateKey, 'hex'),
      rootIpnsPublicKey: Buffer.from(dto.rootIpnsPublicKey, 'hex'),
      rootIpnsName: dto.rootIpnsName,
      initializedAt: null,
    });

    const savedVault = await this.vaultRepository.save(vault);
    return this.toVaultResponse(savedVault);
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

    return this.toVaultResponse(vault);
  }

  /**
   * Check if vault exists for user (returns null if not)
   */
  async findVault(userId: string): Promise<VaultResponseDto | null> {
    const vault = await this.vaultRepository.findOne({
      where: { ownerId: userId },
    });

    return vault ? this.toVaultResponse(vault) : null;
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
   * Convert Vault entity to response DTO with hex-encoded fields
   */
  private toVaultResponse(vault: Vault): VaultResponseDto {
    return {
      id: vault.id,
      ownerPublicKey: vault.ownerPublicKey.toString('hex'),
      encryptedRootFolderKey: vault.encryptedRootFolderKey.toString('hex'),
      encryptedRootIpnsPrivateKey: vault.encryptedRootIpnsPrivateKey.toString('hex'),
      rootIpnsPublicKey: vault.rootIpnsPublicKey.toString('hex'),
      rootIpnsName: vault.rootIpnsName,
      createdAt: vault.createdAt,
      initializedAt: vault.initializedAt,
    };
  }
}
