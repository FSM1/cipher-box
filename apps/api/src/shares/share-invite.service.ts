import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, IsNull, Not } from 'typeorm';
import { randomBytes } from 'crypto';
import { Share } from './entities/share.entity';
import { ShareKey } from './entities/share-key.entity';
import { ShareInvite } from './entities/share-invite.entity';
import { CreateInviteDto } from './dto/create-invite.dto';
import { ClaimInviteDto } from './dto/claim-invite.dto';

/** Default invite expiry: 7 days */
const INVITE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

@Injectable()
export class ShareInviteService {
  private readonly logger = new Logger(ShareInviteService.name);

  constructor(
    @InjectRepository(ShareInvite)
    private readonly inviteRepo: Repository<ShareInvite>,
    private readonly dataSource: DataSource
  ) {}

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

    // Pre-transaction expiry / status check so expired/revoked invites
    // return 404 instead of leaking through to the atomic UPDATE (which
    // would throw 409 and signal that the token exists).
    if (invite.expiresAt < new Date()) {
      if (invite.status === 'active') {
        await this.inviteRepo.remove(invite);
      }
      throw new NotFoundException('Invite not found or expired');
    }

    if (invite.status !== 'active') {
      throw new NotFoundException('Invite not found or expired');
    }

    // Self-claim prevention
    if (invite.sharerId === claimerId) {
      throw new ConflictException('Cannot claim your own invite');
    }

    // Run atomic claim + Share creation inside a transaction so that
    // a failure after marking the invite as claimed is rolled back.
    return this.dataSource.transaction(async (manager) => {
      // Atomic UPDATE to prevent race condition on single-claim
      const result = await manager
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
      const existingShare = await manager.findOne(Share, {
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
      const revoked = await manager.find(Share, {
        where: {
          sharerId: invite.sharerId,
          recipientId: claimerId,
          ipnsName: invite.ipnsName,
          revokedAt: Not(IsNull()),
        },
      });
      if (revoked.length > 0) {
        await manager.remove(revoked);
      }

      // Create Share record with re-wrapped keys from the claim DTO
      const share = manager.create(Share, {
        sharerId: invite.sharerId,
        recipientId: claimerId,
        itemType: invite.itemType,
        ipnsName: invite.ipnsName,
        itemName: invite.itemName,
        encryptedKey: Buffer.from(dto.encryptedKey, 'hex'),
        hiddenByRecipient: false,
        revokedAt: null,
      });

      const savedShare = await manager.save(share);

      // Create ShareKey records from re-wrapped child keys
      if (dto.childKeys && dto.childKeys.length > 0) {
        const shareKeys = dto.childKeys.map((ck) =>
          manager.create(ShareKey, {
            shareId: savedShare.id,
            keyType: ck.keyType,
            itemId: ck.itemId,
            encryptedKey: Buffer.from(ck.encryptedKey, 'hex'),
          })
        );
        await manager.save(shareKeys);
      }

      return { shareId: savedShare.id };
    });
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
