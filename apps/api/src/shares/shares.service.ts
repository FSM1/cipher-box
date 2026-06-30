import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, In } from 'typeorm';
import { Share } from './entities/share.entity';
import { ShareInvite } from './entities/share-invite.entity';
import { User } from '../auth/entities/user.entity';
import { CreateShareDto } from './dto/create-share.dto';

@Injectable()
export class SharesService {
  constructor(
    @InjectRepository(Share)
    private readonly shareRepo: Repository<Share>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    private readonly dataSource: DataSource
  ) {}

  /**
   * Create a new share record with descriptor refs (DATA-02).
   * Validates recipient exists and is not the sharer.
   * Prevents duplicate grants for the same root node / recipient pair.
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

    // Hard-delete on revoke means no revoked rows remain — plain unique check suffices
    const existing = await this.shareRepo.findOne({
      where: {
        sharerId,
        recipientId: recipient.id,
        rootNodeId: dto.rootNodeId,
      },
    });

    if (existing) {
      throw new ConflictException('Share already exists for this item and recipient');
    }

    const share = this.shareRepo.create({
      sharerId,
      recipientId: recipient.id,
      readDescriptorRef: Buffer.from(dto.readDescriptorRef, 'hex'),
      writeDescriptorRef: dto.writeDescriptorRef
        ? Buffer.from(dto.writeDescriptorRef, 'hex')
        : null,
      rootNodeId: dto.rootNodeId,
      rootIpnsName: dto.rootIpnsName,
      rootGeneration: dto.rootGeneration ?? '0',
      itemNameEncrypted: dto.itemNameEncrypted ? Buffer.from(dto.itemNameEncrypted, 'hex') : null,
      hiddenByRecipient: false,
    });

    try {
      return await this.shareRepo.save(share);
    } catch (err: unknown) {
      // Handle race condition: concurrent createShare for the same triple
      if (err instanceof Error && err.message?.includes('duplicate key')) {
        throw new ConflictException('Share already exists for this item and recipient');
      }
      throw err;
    }
  }

  /**
   * Get non-hidden shares received by the user (paginated).
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
   * Get shares sent by the user (paginated).
   * Includes recipient relation for publicKey display.
   */
  async getSentShares(
    sharerId: string,
    limit: number,
    offset: number
  ): Promise<{ shares: Share[]; total: number }> {
    const [shares, total] = await this.shareRepo.findAndCount({
      where: { sharerId },
      relations: ['recipient'],
      order: { createdAt: 'DESC' },
      take: limit,
      skip: offset,
    });
    return { shares, total };
  }

  /**
   * Hard-delete a share grant (D-11 forward-only revocation).
   * Only the sharer can revoke.
   */
  async revokeShare(shareId: string, sharerId: string): Promise<void> {
    const share = await this.shareRepo.findOne({ where: { id: shareId } });

    if (!share) {
      throw new NotFoundException('Share not found');
    }

    if (share.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can revoke a share');
    }

    await this.shareRepo.remove(share);
  }

  /**
   * Hard-revoke every share/invite the caller created for ANY of the given IPNS
   * names, in a single transaction. Used when an owner deletes an item (file or
   * folder subtree) to the recycle bin.
   *
   * - Shares: HARD-deleted by rootIpnsName (D-11).
   * - Invites: active ShareInvite rows are marked 'revoked'.
   *
   * Scoped to `sharerId = caller` so a user can only revoke their own shares.
   *
   * @returns Counts of hard-deleted shares and revoked invites.
   */
  async revokeForItems(
    sharerId: string,
    ipnsNames: string[]
  ): Promise<{ revokedShares: number; revokedInvites: number }> {
    const uniqueNames = [...new Set(ipnsNames)];
    if (uniqueNames.length === 0) {
      return { revokedShares: 0, revokedInvites: 0 };
    }

    return this.dataSource.transaction(async (manager) => {
      const shares = await manager.find(Share, {
        where: { sharerId, rootIpnsName: In(uniqueNames) },
      });
      if (shares.length > 0) {
        await manager.remove(shares);
      }

      // Mark active invites for these items as revoked
      const inviteResult = await manager
        .createQueryBuilder()
        .update(ShareInvite)
        .set({ status: 'revoked' })
        .where('sharer_id = :sharerId', { sharerId })
        .andWhere('root_ipns_name IN (:...names)', { names: uniqueNames })
        .andWhere('status = :status', { status: 'active' })
        .execute();

      return {
        revokedShares: shares.length,
        revokedInvites: inviteResult.affected ?? 0,
      };
    });
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
   * Backfill the at-rest itemNameEncrypted ciphertext on a share.
   * Only the sharer can update it (they hold the recipient pubkey to re-wrap).
   * The server never encrypts — it persists the client-supplied ciphertext as-is.
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
}
