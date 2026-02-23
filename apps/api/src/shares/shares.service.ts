import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull, Not } from 'typeorm';
import { randomBytes } from 'crypto';
import { Share } from './entities/share.entity';
import { ShareKey } from './entities/share-key.entity';
import { ShareInvite } from './entities/share-invite.entity';
import { User } from '../auth/entities/user.entity';
import { CreateShareDto } from './dto/create-share.dto';
import { AddShareKeysDto } from './dto/share-key.dto';
import { CreateInviteDto } from './dto/create-invite.dto';
import { ClaimInviteDto } from './dto/claim-invite.dto';

/** Default invite expiry: 7 days */
const INVITE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

@Injectable()
export class SharesService {
  private readonly logger = new Logger(SharesService.name);

  constructor(
    @InjectRepository(Share)
    private readonly shareRepo: Repository<Share>,
    @InjectRepository(ShareKey)
    private readonly shareKeyRepo: Repository<ShareKey>,
    @InjectRepository(ShareInvite)
    private readonly inviteRepo: Repository<ShareInvite>,
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

  // ──────────────────────────────────────────────────────
  // Invite link methods (Phase 15)
  // ──────────────────────────────────────────────────────

  /**
   * Create an invite record with a random token and 7-day expiry.
   * The encryptedKey is the item key wrapped with an ephemeral public key.
   */
  async createInvite(sharerId: string, dto: CreateInviteDto): Promise<ShareInvite> {
    const token = randomBytes(16).toString('base64url');
    const expiresAt = new Date(Date.now() + INVITE_EXPIRY_MS);

    const invite = this.inviteRepo.create({
      token,
      sharerId,
      itemType: dto.itemType,
      ipnsName: dto.ipnsName,
      itemName: dto.itemName,
      encryptedKey: Buffer.from(dto.encryptedKey, 'hex'),
      encryptedChildKeys: dto.encryptedChildKeys ?? null,
      status: 'active',
      maxClaims: 1,
      claimCount: 0,
      expiresAt,
    });

    return this.inviteRepo.save(invite);
  }

  /**
   * Get invite status by token (public, no auth).
   * Auto-expires and hard-deletes if past TTL.
   * Returns null if not found (controller maps to 'expired').
   */
  async getInviteStatus(token: string): Promise<{ status: string } | null> {
    const invite = await this.inviteRepo.findOne({ where: { token } });

    if (!invite) return null;

    // Auto-expire: delete and return null if past expiry
    if (invite.status === 'active' && invite.expiresAt < new Date()) {
      await this.inviteRepo.remove(invite);
      return null;
    }

    return { status: invite.status };
  }

  /**
   * Get full invite data for the claim flow (authenticated).
   * Returns encryptedKey, encryptedChildKeys, itemType, ipnsName, itemName.
   * Auto-expires and returns null if past TTL.
   */
  async getInviteForClaim(token: string): Promise<ShareInvite | null> {
    const invite = await this.inviteRepo.findOne({ where: { token } });

    if (!invite) return null;

    // Auto-expire: delete and return null if past expiry
    if (invite.status === 'active' && invite.expiresAt < new Date()) {
      await this.inviteRepo.remove(invite);
      return null;
    }

    // Only return active invites for the claim flow
    if (invite.status !== 'active') return null;

    return invite;
  }

  /**
   * Claim an invite: atomic single-claim with Share + ShareKey creation.
   *
   * Uses UPDATE ... WHERE to prevent race conditions on concurrent claims.
   * Self-claim prevention: sharer cannot claim their own invite.
   * Creates standard Phase 14 Share + ShareKey records from re-wrapped keys.
   */
  async claimInvite(
    token: string,
    claimerId: string,
    dto: ClaimInviteDto
  ): Promise<{ shareId: string }> {
    // First, look up the invite to get sharer info
    const invite = await this.inviteRepo.findOne({ where: { token } });

    if (!invite) {
      throw new NotFoundException('Invite not found or expired');
    }

    // Self-claim prevention
    if (invite.sharerId === claimerId) {
      throw new ConflictException('Cannot claim your own invite');
    }

    // Atomic UPDATE to prevent race condition on single-claim
    const result = await this.inviteRepo
      .createQueryBuilder()
      .update(ShareInvite)
      .set({
        status: 'claimed',
        claimedBy: claimerId,
        claimCount: () => 'claim_count + 1',
      })
      .where('token = :token', { token })
      .andWhere('status = :status', { status: 'active' })
      .andWhere('claim_count < max_claims')
      .andWhere('expires_at > NOW()')
      .execute();

    if (!result.affected || result.affected < 1) {
      throw new ConflictException('Invite already claimed, expired, or revoked');
    }

    // Check for existing active share (same sharer, recipient, ipnsName)
    const existingShare = await this.shareRepo.findOne({
      where: {
        sharerId: invite.sharerId,
        recipientId: claimerId,
        ipnsName: invite.ipnsName,
        revokedAt: IsNull(),
      },
    });

    if (existingShare) {
      this.logger.warn(
        `Invite claim for ${invite.ipnsName}: share already exists between ${invite.sharerId} and ${claimerId}`
      );
      return { shareId: existingShare.id };
    }

    // Clean up any revoked-but-not-yet-rotated records for this triple
    const revoked = await this.shareRepo.find({
      where: {
        sharerId: invite.sharerId,
        recipientId: claimerId,
        ipnsName: invite.ipnsName,
        revokedAt: Not(IsNull()),
      },
    });
    if (revoked.length > 0) {
      await this.shareRepo.remove(revoked);
    }

    // Create Share record with re-wrapped keys from the claim DTO
    const share = this.shareRepo.create({
      sharerId: invite.sharerId,
      recipientId: claimerId,
      itemType: invite.itemType,
      ipnsName: invite.ipnsName,
      itemName: invite.itemName,
      encryptedKey: Buffer.from(dto.encryptedKey, 'hex'),
      hiddenByRecipient: false,
      revokedAt: null,
    });

    const savedShare = await this.shareRepo.save(share);

    // Create ShareKey records from re-wrapped child keys
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

    return { shareId: savedShare.id };
  }

  /**
   * Get active invites for a specific item created by a sharer.
   * Auto-cleans expired invites during the query.
   */
  async getInvitesForItem(sharerId: string, ipnsName: string): Promise<ShareInvite[]> {
    const invites = await this.inviteRepo.find({
      where: {
        sharerId,
        ipnsName,
        status: 'active',
      },
      order: { createdAt: 'DESC' },
    });

    // Auto-clean expired invites
    const now = new Date();
    const expired = invites.filter((inv) => inv.expiresAt < now);
    const active = invites.filter((inv) => inv.expiresAt >= now);

    if (expired.length > 0) {
      await this.inviteRepo.remove(expired);
    }

    return active;
  }

  /**
   * Revoke an invite link. Only the original sharer can revoke.
   * Already-claimed shares are unaffected.
   */
  async revokeInvite(inviteId: string, sharerId: string): Promise<void> {
    const invite = await this.inviteRepo.findOne({ where: { id: inviteId } });

    if (!invite) {
      throw new NotFoundException('Invite not found');
    }

    if (invite.sharerId !== sharerId) {
      throw new ForbiddenException('Only the sharer can revoke an invite');
    }

    invite.status = 'revoked';
    await this.inviteRepo.save(invite);
  }
}
