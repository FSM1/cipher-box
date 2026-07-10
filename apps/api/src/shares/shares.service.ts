import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Share } from './entities/share.entity';
import { ShareInvite } from './entities/share-invite.entity';
import { User } from '../auth/entities/user.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { CreateShareDto } from './dto/create-share.dto';

@Injectable()
export class SharesService {
  constructor(
    @InjectRepository(Share)
    private readonly shareRepo: Repository<Share>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(IpnsRecord)
    private readonly ipnsRecordRepo: Repository<IpnsRecord>,
    private readonly dataSource: DataSource
  ) {}

  /**
   * Create a new share record with encrypted keys (DATA-02).
   * Validates recipient exists and is not the sharer.
   * Prevents duplicate grants for the same root node / recipient pair.
   */
  async createShare(sharerId: string, dto: CreateShareDto): Promise<Share> {
    // D-01/SC#1 root-ownership gate (defense-in-depth, non-authoritative): reads the
    // ipns_records creator marker to reject callers who never registered this node.
    // The true access boundary is cryptographic (the sharer can only wrap keys they
    // hold) — this is a cheap anti-spoof check atop that boundary. Per D-02, only
    // shareRootIpnsName ownership is verified here; rootNodeId stays client-asserted.
    // Runs fail-fast, before the recipient lookup.
    const owned = await this.ipnsRecordRepo.findOne({
      where: { ipnsName: dto.shareRootIpnsName, userId: sharerId },
    });
    if (!owned) {
      throw new ForbiddenException('You are not the registered owner of this node');
    }

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
      encryptedReadKey: Buffer.from(dto.encryptedReadKey, 'hex'),
      encryptedWriteKey: dto.encryptedWriteKey ? Buffer.from(dto.encryptedWriteKey, 'hex') : null,
      rootNodeId: dto.rootNodeId,
      shareRootIpnsName: dto.shareRootIpnsName,
      rootGeneration: dto.rootGeneration ?? '0',
      itemNameEncrypted: dto.itemNameEncrypted ? Buffer.from(dto.itemNameEncrypted, 'hex') : null,
      hiddenByRecipient: false,
    });

    try {
      return await this.shareRepo.save(share);
    } catch (err: unknown) {
      // Handle race condition: concurrent createShare for the same triple.
      // Detect Postgres unique-violation (SQLSTATE 23505) on the error code,
      // not a brittle message substring.
      const code = (err as { code?: string; driverError?: { code?: string } }).code;
      const driverCode = (err as { driverError?: { code?: string } }).driverError?.code;
      if (code === '23505' || driverCode === '23505') {
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
   * - Shares: HARD-deleted by shareRootIpnsName (D-11).
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
      const shareResult = await manager
        .createQueryBuilder()
        .delete()
        .from(Share)
        .where('sharer_id = :sharerId', { sharerId })
        .andWhere('share_root_ipns_name IN (:...names)', { names: uniqueNames })
        .execute();

      // Mark active invites for these items as revoked
      const inviteResult = await manager
        .createQueryBuilder()
        .update(ShareInvite)
        .set({ status: 'revoked' })
        .where('sharer_id = :sharerId', { sharerId })
        .andWhere('share_root_ipns_name IN (:...names)', { names: uniqueNames })
        .andWhere('status = :status', { status: 'active' })
        .execute();

      return {
        revokedShares: shareResult.affected ?? 0,
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
   * Persist a rotated encryptedReadKey and rootGeneration on an existing share.
   * Only the sharer (owner) can update it — the owner drives grant re-mint on
   * key rotation (D-10/D-11, 68-07 owner reconcile). The server never
   * re-encrypts — it persists the client-supplied ciphertext as-is.
   *
   * `encryptedWriteKey`/`clearEncryptedWriteKey` additionally support the
   * read->write upgrade / write->read downgrade paths (68.1-19): when
   * `encryptedWriteKey` is supplied, it sets the share's write key
   * (upgrade). When `clearEncryptedWriteKey` is true, it clears the share's
   * write key to null (downgrade). When neither is supplied — the
   * existing read-key-rotation-only call shape (owner-reconcile,
   * D-10/D-11) — `encryptedWriteKey` is left completely unchanged (T-68.1-19-02).
   * The two are mutually exclusive.
   */
  async updateGrant(
    shareId: string,
    sharerId: string,
    encryptedReadKey: string,
    rootGeneration: string,
    encryptedWriteKey?: string,
    clearEncryptedWriteKey?: boolean
  ): Promise<void> {
    if (encryptedWriteKey && clearEncryptedWriteKey) {
      throw new BadRequestException(
        'encryptedWriteKey and clearEncryptedWriteKey are mutually exclusive'
      );
    }

    // Row-locked transaction: the anti-rollback check below must see the row
    // a concurrent PATCH just committed, not a stale pre-race read (TOCTOU).
    await this.dataSource.transaction(async (manager) => {
      const share = await manager.findOne(Share, {
        where: { id: shareId },
        lock: { mode: 'pessimistic_write' },
      });

      if (!share) {
        throw new NotFoundException('Share not found');
      }

      if (share.sharerId !== sharerId) {
        throw new ForbiddenException('Only the sharer can update the grant');
      }

      // Anti-rollback: the grant's rootGeneration seeds the recipient's durable
      // generation floor on first contact, so a replayed/duplicate PATCH must
      // never regress it below the stored value.
      if (BigInt(rootGeneration) < BigInt(share.rootGeneration)) {
        throw new ConflictException(
          'rootGeneration regression rejected: grants only advance the generation'
        );
      }

      share.encryptedReadKey = Buffer.from(encryptedReadKey, 'hex');
      share.rootGeneration = rootGeneration;
      if (clearEncryptedWriteKey) {
        share.encryptedWriteKey = null;
      } else if (encryptedWriteKey) {
        share.encryptedWriteKey = Buffer.from(encryptedWriteKey, 'hex');
      }
      // else: leave share.encryptedWriteKey untouched (read-only rotation).
      await manager.save(share);
    });
  }
}
