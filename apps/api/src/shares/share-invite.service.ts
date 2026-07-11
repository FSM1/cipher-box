import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { randomBytes } from 'crypto';
import { Share } from './entities/share.entity';
import { ShareInvite } from './entities/share-invite.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { CreateInviteDto } from './dto/create-invite.dto';
import { ClaimInviteDto } from './dto/claim-invite.dto';
import { assertRootOwnership } from './root-ownership.util';

/** Default invite expiry: 7 days */
const INVITE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

@Injectable()
export class ShareInviteService {
  private readonly logger = new Logger(ShareInviteService.name);

  constructor(
    @InjectRepository(ShareInvite)
    private readonly inviteRepo: Repository<ShareInvite>,
    @InjectRepository(IpnsRecord)
    private readonly ipnsRecordRepo: Repository<IpnsRecord>,
    private readonly dataSource: DataSource
  ) {}

  /**
   * Create an invite record with a random token and 7-day expiry.
   * The encryptedReadKey is the root readKey wrapped with an ephemeral public key.
   */
  async createInvite(sharerId: string, dto: CreateInviteDto): Promise<ShareInvite> {
    // D-01/SC#1 root-ownership gate (defense-in-depth, non-authoritative) — see
    // assertRootOwnership for details.
    await assertRootOwnership(this.ipnsRecordRepo, dto.shareRootIpnsName, sharerId);

    const token = randomBytes(16).toString('base64url');
    const expiresAt = new Date(Date.now() + INVITE_EXPIRY_MS);

    const invite = this.inviteRepo.create({
      token,
      sharerId,
      shareRootIpnsName: dto.shareRootIpnsName,
      rootNodeId: dto.rootNodeId,
      rootGeneration: dto.rootGeneration ?? '0',
      // Client-supplied ECIES ciphertext (wrapped with the ephemeral pubkey).
      // Server never encrypts plaintext (zero-knowledge).
      itemNameEncrypted: dto.itemNameEncrypted ? Buffer.from(dto.itemNameEncrypted, 'hex') : null,
      encryptedReadKey: Buffer.from(dto.encryptedReadKey, 'hex'),
      encryptedWriteKey: dto.encryptedWriteKey ? Buffer.from(dto.encryptedWriteKey, 'hex') : null,
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
   * Returns encryptedReadKey, encryptedWriteKey, rootNodeId, shareRootIpnsName, rootGeneration.
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
   * Claim an invite: atomic single-claim that mints one encrypted-key Share (D-05).
   *
   * Uses UPDATE ... WHERE to prevent race conditions on concurrent claims.
   * Self-claim prevention: sharer cannot claim their own invite.
   * Root identity is copied from the invite row, not from claimer input.
   * Single encrypted-key grant — no fan-out (DATA-01/DATA-02).
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
    // return 404 instead of leaking through to the atomic UPDATE
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

    // A write-capable invite MUST be claimed with a re-wrapped write key. Without this
    // guard the invite is still atomically consumed below while the minted (or widened)
    // share silently drops to read-only (encryptedWriteKey = null) — the recipient burns a
    // write invite and permanently loses the write grant they were entitled to. Reject
    // BEFORE the transaction so the invite is NOT consumed. Read-only invites are exempt;
    // write authority stays invite-derived (T-66-E1).
    if (invite.encryptedWriteKey !== null && !dto.encryptedWriteKey) {
      throw new BadRequestException(
        'This invite grants write access — a re-wrapped encryptedWriteKey is required to claim it'
      );
    }

    // Run atomic claim + Share creation inside a transaction
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

      // Check for existing share (same sharer, recipient, rootNodeId — hard-delete means
      // no revoked rows remain, so plain triple lookup suffices)
      const existingShare = await manager.findOne(Share, {
        where: {
          sharerId: invite.sharerId,
          recipientId: claimerId,
          rootNodeId: invite.rootNodeId,
        },
      });

      if (existingShare) {
        // D-07/SC#2: a re-claim over an already-existing share applies the later
        // invite's grant ONLY if it WIDENS authority (read→write, or a higher
        // rootGeneration). A same-level or lower re-claim is a true no-op — no
        // manager.save, no field mutation. Write authority is presence-derived
        // (T-66-E1): every field write below is individually gated so a
        // non-widening re-claim can never null out an existing encryptedWriteKey.
        // This runs AFTER the atomic claim UPDATE above (already committed inside
        // this same transaction manager) — the invite is validly consumed for a
        // legitimate widen, and a redundant re-claim still burns the invite without
        // silently dropping (or downgrading) the existing grant.
        const inviteGrantsWrite = invite.encryptedWriteKey !== null;
        const existingHasWrite = existingShare.encryptedWriteKey !== null;
        const isWriteUpgrade = inviteGrantsWrite && !existingHasWrite;
        const isGenerationBump =
          BigInt(invite.rootGeneration) > BigInt(existingShare.rootGeneration);

        if (isWriteUpgrade || isGenerationBump) {
          existingShare.encryptedReadKey = Buffer.from(dto.encryptedReadKey, 'hex');
          // Refresh the write key when the claimer supplies one AND write authority is
          // (re)established at the new generation: either a read→write upgrade, OR a
          // generation bump on an already-write-capable share via a write-capable invite.
          // Without the generation-bump arm, a bump would advance encryptedReadKey +
          // rootGeneration while leaving encryptedWriteKey wrapped for the OLD generation's
          // key material — the recipient would silently lose write capability post-rotation.
          // Still presence-gated on dto.encryptedWriteKey so a non-widening / read-only
          // re-claim can never null out an existing write grant (T-66-E1).
          if (
            (isWriteUpgrade || (isGenerationBump && inviteGrantsWrite)) &&
            dto.encryptedWriteKey
          ) {
            existingShare.encryptedWriteKey = Buffer.from(dto.encryptedWriteKey, 'hex');
          }
          if (isGenerationBump) {
            existingShare.rootGeneration = invite.rootGeneration;
          }
          await manager.save(existingShare);
        } else {
          this.logger.warn(
            `Invite claim for ${invite.shareRootIpnsName}: share already exists between ${invite.sharerId} and ${claimerId} and does not widen authority — no-op`
          );
        }

        return { shareId: existingShare.id };
      }

      // Mint exactly one encrypted-key Share (D-05).
      // Root identity is sourced from the invite row to prevent spoofing (T-66-S1).
      // Write grant is presence-derived from the INVITE, not claimer input (T-66-E1):
      // a read-only invite (invite.encryptedWriteKey === null) can never yield a
      // write grant even if the claimer supplies an encryptedWriteKey in the claim
      // body. The stored value is still the claimer's re-wrapped key (wrapped for the
      // recipient's pubkey); the invite only gates whether write authority exists.
      // itemNameEncrypted is re-wrapped client-side for the recipient's real pubkey.
      const inviteGrantsWrite = invite.encryptedWriteKey !== null;
      const share = manager.create(Share, {
        sharerId: invite.sharerId,
        recipientId: claimerId,
        encryptedReadKey: Buffer.from(dto.encryptedReadKey, 'hex'),
        encryptedWriteKey:
          inviteGrantsWrite && dto.encryptedWriteKey
            ? Buffer.from(dto.encryptedWriteKey, 'hex')
            : null,
        rootNodeId: invite.rootNodeId,
        shareRootIpnsName: invite.shareRootIpnsName,
        rootGeneration: invite.rootGeneration,
        itemNameEncrypted: dto.itemNameEncrypted ? Buffer.from(dto.itemNameEncrypted, 'hex') : null,
        hiddenByRecipient: false,
      });

      const savedShare = await manager.save(share);

      return { shareId: savedShare.id };
    });
  }

  /**
   * Get active invites for a specific item created by a sharer.
   * Auto-cleans expired invites during the query.
   */
  async getInvitesForItem(sharerId: string, shareRootIpnsName: string): Promise<ShareInvite[]> {
    const invites = await this.inviteRepo.find({
      where: {
        sharerId,
        shareRootIpnsName,
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
