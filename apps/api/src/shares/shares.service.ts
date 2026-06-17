import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull, Not, In } from 'typeorm';
import { Share } from './entities/share.entity';
import { ShareKey } from './entities/share-key.entity';
import { User } from '../auth/entities/user.entity';
import { CreateShareDto } from './dto/create-share.dto';
import { AddShareKeysDto } from './dto/share-key.dto';

@Injectable()
export class SharesService {
  constructor(
    @InjectRepository(Share)
    private readonly shareRepo: Repository<Share>,
    @InjectRepository(ShareKey)
    private readonly shareKeyRepo: Repository<ShareKey>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>
  ) {}

  /**
   * Create a new share record with re-wrapped keys.
   * Validates recipient exists and is not the sharer.
   * Prevents duplicate active shares for the same item/recipient pair.
   */
  async createShare(sharerId: string, dto: CreateShareDto): Promise<Share> {
    // Look up recipient by publicKey
    // Strip 0x prefix if present — DB stores bare hex
    const normalizedPubKey = dto.recipientPublicKey.startsWith('0x')
      ? dto.recipientPublicKey.slice(2)
      : dto.recipientPublicKey;
    const recipient = await this.userRepo.findOne({
      where: { publicKey: normalizedPubKey },
    });

    if (!recipient) {
      throw new NotFoundException('Recipient not found');
    }

    if (recipient.id === sharerId) {
      throw new ConflictException('Cannot share with yourself');
    }

    // Check for existing active share (same sharer, recipient, ipnsName)
    const existing = await this.shareRepo.findOne({
      where: {
        sharerId,
        recipientId: recipient.id,
        ipnsName: dto.ipnsName,
        revokedAt: IsNull(),
      },
    });

    if (existing) {
      throw new ConflictException('Share already exists for this item and recipient');
    }

    // Clean up any revoked-but-not-yet-rotated records for this triple
    // so the new share can be created without unique constraint conflicts
    const revoked = await this.shareRepo.find({
      where: {
        sharerId,
        recipientId: recipient.id,
        ipnsName: dto.ipnsName,
        revokedAt: Not(IsNull()),
      },
    });
    if (revoked.length > 0) {
      await this.shareRepo.remove(revoked);
    }

    // Validate permission/IPNS-key invariant
    const permission = dto.permission ?? 'read';
    let encryptedIpnsKey: Buffer | null = null;

    if (permission === 'write') {
      if (!dto.encryptedIpnsKey) {
        throw new BadRequestException('encryptedIpnsKey required for write permission');
      }
      encryptedIpnsKey = Buffer.from(dto.encryptedIpnsKey, 'hex');
    } else if (dto.encryptedIpnsKey) {
      throw new BadRequestException('encryptedIpnsKey must be omitted for read permission');
    }

    const share = this.shareRepo.create({
      sharerId,
      recipientId: recipient.id,
      itemType: dto.itemType,
      ipnsName: dto.ipnsName,
      itemName: dto.itemName,
      // Client-supplied ECIES ciphertext only. The server is zero-knowledge:
      // it never sees the plaintext name and never encrypts it (no recipient
      // private key). Legacy clients omit this and still send plaintext itemName.
      itemNameEncrypted: dto.itemNameEncrypted ? Buffer.from(dto.itemNameEncrypted, 'hex') : null,
      encryptedKey: Buffer.from(dto.encryptedKey, 'hex'),
      permission,
      encryptedIpnsKey,
      hiddenByRecipient: false,
      revokedAt: null,
    });

    let savedShare: typeof share;
    try {
      savedShare = await this.shareRepo.save(share);
    } catch (err: unknown) {
      // Handle race condition: concurrent createShare for the same triple
      if (err instanceof Error && err.message?.includes('duplicate key')) {
        throw new ConflictException('Share already exists for this item and recipient');
      }
      throw err;
    }

    // Create child keys if provided
    if (dto.childKeys && dto.childKeys.length > 0) {
      const shareKeys = dto.childKeys.map((ck) =>
        this.shareKeyRepo.create({
          shareId: savedShare.id,
          keyType: ck.keyType,
          itemId: ck.itemId,
          encryptedKey: Buffer.from(ck.encryptedKey, 'hex'),
        })
      );
      await this.shareKeyRepo.save(shareKeys);
    }

    return savedShare;
  }

  /**
   * Get active, non-hidden shares received by the user (paginated).
   * Includes sharer relation for publicKey display.
   */
  async getReceivedShares(
    recipientId: string,
    limit: number,
    offset: number
  ): Promise<{ shares: Share[]; total: number }> {
    const [shares, total] = await this.shareRepo.findAndCount({
      where: {
        recipientId,
        revokedAt: IsNull(),
        hiddenByRecipient: false,
      },
      relations: ['sharer'],
      order: { createdAt: 'DESC' },
      take: limit,
      skip: offset,
    });
    return { shares, total };
  }

  /**
   * Get active shares sent by the user (paginated).
   * Includes recipient relation for publicKey display.
   */
  async getSentShares(
    sharerId: string,
    limit: number,
    offset: number
  ): Promise<{ shares: Share[]; total: number }> {
    const [shares, total] = await this.shareRepo.findAndCount({
      where: {
        sharerId,
        revokedAt: IsNull(),
      },
      relations: ['recipient'],
      order: { createdAt: 'DESC' },
      take: limit,
      skip: offset,
    });
    return { shares, total };
  }

  /**
   * Get all re-wrapped child keys for a share.
   * Validates the requesting user is either sharer or recipient.
   */
  async getShareKeys(shareId: string, userId: string): Promise<ShareKey[]> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== userId && share.recipientId !== userId) {
      throw new ForbiddenException('Not authorized to access this share');
    }

    return this.shareKeyRepo.find({
      where: { shareId },
      order: { createdAt: 'ASC' },
    });
  }

  /**
   * Add or update re-wrapped keys for an existing share.
   * Allowed for the sharer (owner) or for write-share recipients.
   */
  async addShareKeys(shareId: string, callerId: string, dto: AddShareKeysDto): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    const isSharer = share.sharerId === callerId;
    const isWriteRecipient =
      share.recipientId === callerId &&
      share.permission === 'write' &&
      share.encryptedIpnsKey !== null &&
      !share.revokedAt;

    if (!isSharer && !isWriteRecipient) {
      throw new ForbiddenException('Only the sharer or write-share recipient can add keys');
    }

    // Note: write-share recipients may add any key type to share_keys.
    // This includes 'folder' keys for subfolders they create — the root
    // folder key is stored in the shares table, not share_keys.

    // Upsert: insert or update encrypted_key for each itemId
    for (const entry of dto.keys) {
      const existing = await this.shareKeyRepo.findOne({
        where: {
          shareId,
          keyType: entry.keyType,
          itemId: entry.itemId,
        },
      });

      if (existing) {
        existing.encryptedKey = Buffer.from(entry.encryptedKey, 'hex');
        await this.shareKeyRepo.save(existing);
      } else {
        const shareKey = this.shareKeyRepo.create({
          shareId,
          keyType: entry.keyType,
          itemId: entry.itemId,
          encryptedKey: Buffer.from(entry.encryptedKey, 'hex'),
        });
        await this.shareKeyRepo.save(shareKey);
      }
    }
  }

  /**
   * Soft-delete a share by setting revokedAt.
   * Only the sharer can revoke. ShareKey records are kept for lazy rotation.
   */
  async revokeShare(shareId: string, sharerId: string): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can revoke a share');
    }

    share.revokedAt = new Date();
    await this.shareRepo.save(share);
  }

  /**
   * Hide a share from the recipient's view.
   * Only the recipient can hide a share.
   */
  async hideShare(shareId: string, recipientId: string): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.recipientId !== recipientId) {
      throw new ForbiddenException('Only the recipient can hide a share');
    }

    share.hiddenByRecipient = true;
    await this.shareRepo.save(share);
  }

  /**
   * Check if a user with the given secp256k1 public key exists.
   * Used to verify recipient is registered before sharing.
   * Does not expose internal user IDs.
   */
  async lookupUserByPublicKey(publicKey: string): Promise<boolean> {
    // Strip 0x prefix if present — DB stores bare hex
    const normalizedKey = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;
    const user = await this.userRepo.findOne({
      where: { publicKey: normalizedKey },
      select: ['id'],
    });

    return !!user;
  }

  /**
   * Get shares pending key rotation (revoked but not yet hard-deleted).
   */
  async getPendingRotations(sharerId: string): Promise<Share[]> {
    return this.shareRepo.find({
      where: {
        sharerId,
        revokedAt: Not(IsNull()),
      },
      relations: ['recipient'],
      order: { revokedAt: 'ASC' },
    });
  }

  /**
   * Hard-delete a share and all associated keys after rotation is complete.
   * Only the sharer can complete the rotation.
   */
  async completeRotation(shareId: string, sharerId: string): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can complete rotation');
    }

    if (!share.revokedAt) {
      throw new ConflictException('Cannot complete rotation for a non-revoked share');
    }

    // CASCADE will remove all associated ShareKey records
    await this.shareRepo.remove(share);
  }

  /**
   * Update the encrypted key on an existing share.
   * Used after lazy key rotation to re-wrap the new folder key for remaining recipients.
   */
  async updateShareEncryptedKey(
    shareId: string,
    sharerId: string,
    encryptedKey: string
  ): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can update share keys');
    }

    share.encryptedKey = Buffer.from(encryptedKey, 'hex');
    await this.shareRepo.save(share);
  }

  /**
   * Backfill the at-rest itemNameEncrypted ciphertext on a legacy share.
   * Only the sharer can update it (they hold the recipient pubkey to re-wrap).
   * The server never encrypts — it persists the client-supplied ciphertext as-is.
   * Used by the decision-A2 lazy backfill for rows created before at-rest
   * itemName encryption existed.
   */
  async updateShareItemName(
    shareId: string,
    sharerId: string,
    itemNameEncrypted: string
  ): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can update the item name');
    }

    share.itemNameEncrypted = Buffer.from(itemNameEncrypted, 'hex');
    await this.shareRepo.save(share);
  }

  /**
   * Update the permission level of a share.
   * Only the sharer (owner) can upgrade or downgrade permission.
   * Upgrading to 'write' requires an ECIES-wrapped IPNS private key.
   * Downgrading to 'read' clears the IPNS key.
   */
  async updatePermission(
    shareId: string,
    sharerId: string,
    permission: 'read' | 'write',
    encryptedIpnsKey?: string
  ): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can change permission');
    }

    if (share.revokedAt) {
      throw new ConflictException('Cannot change permission on a revoked share');
    }

    if (permission === 'write') {
      if (!encryptedIpnsKey) {
        throw new BadRequestException('encryptedIpnsKey required for write permission');
      }
      share.permission = 'write';
      share.encryptedIpnsKey = Buffer.from(encryptedIpnsKey, 'hex');
      await this.shareRepo.save(share);
    } else {
      // Downgrade atomically: update share + delete all write-enabling keys in one transaction
      await this.shareRepo.manager.transaction(async (txManager) => {
        share.permission = 'read';
        share.encryptedIpnsKey = null;
        await txManager.save(share);
        await txManager.delete(ShareKey, { shareId, keyType: In(['file-ipns', 'folder-ipns']) });
      });
    }
  }

  /**
   * Find an active write share for a given recipient and IPNS name.
   * Used by IPNS publish authorization to allow write-share recipients to publish.
   */
  async findActiveWriteShare(recipientId: string, ipnsName: string): Promise<Share | null> {
    return this.shareRepo.findOne({
      where: {
        recipientId,
        ipnsName,
        permission: 'write',
        encryptedIpnsKey: Not(IsNull()),
        revokedAt: IsNull(),
      },
    });
  }
}
