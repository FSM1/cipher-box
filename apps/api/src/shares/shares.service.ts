import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull, Not } from 'typeorm';
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
    const recipient = await this.userRepo.findOne({
      where: { publicKey: dto.recipientPublicKey },
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

    const share = this.shareRepo.create({
      sharerId,
      recipientId: recipient.id,
      itemType: dto.itemType,
      ipnsName: dto.ipnsName,
      itemName: dto.itemName,
      encryptedKey: Buffer.from(dto.encryptedKey, 'hex'),
      hiddenByRecipient: false,
      revokedAt: null,
    });

    const savedShare = await this.shareRepo.save(share);

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
   * Get all active, non-hidden shares received by the user.
   * Includes sharer relation for publicKey display.
   */
  async getReceivedShares(recipientId: string): Promise<Share[]> {
    return this.shareRepo.find({
      where: {
        recipientId,
        revokedAt: IsNull(),
        hiddenByRecipient: false,
      },
      relations: ['sharer'],
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Get all active shares sent by the user.
   * Includes recipient relation for publicKey display.
   */
  async getSentShares(sharerId: string): Promise<Share[]> {
    return this.shareRepo.find({
      where: {
        sharerId,
        revokedAt: IsNull(),
      },
      relations: ['recipient'],
      order: { createdAt: 'DESC' },
    });
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
   * Only the sharer can add keys.
   */
  async addShareKeys(shareId: string, sharerId: string, dto: AddShareKeysDto): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can add keys');
    }

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
   * Look up a user by their secp256k1 public key.
   * Used to verify recipient exists before sharing.
   */
  async lookupUserByPublicKey(
    publicKey: string
  ): Promise<{ userId: string; publicKey: string } | null> {
    const user = await this.userRepo.findOne({
      where: { publicKey },
    });

    if (!user) {
      return null;
    }

    return { userId: user.id, publicKey: user.publicKey };
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
}
