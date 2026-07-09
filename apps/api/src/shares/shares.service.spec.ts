import { Test, TestingModule } from '@nestjs/testing';
import {
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { DataSource, In } from 'typeorm';
import { SharesService } from './shares.service';
import { Share } from './entities/share.entity';
import { ShareInvite } from './entities/share-invite.entity';
import { User } from '../auth/entities/user.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { CreateShareDto } from './dto/create-share.dto';

type RepoMock = jest.Mocked<Record<string, jest.Mock>>;

// A valid uncompressed secp256k1 pubkey: 04 + 128 hex chars (DTO shape, stored bare).
const BARE_PUBKEY = '04' + 'ab'.repeat(64);
const SHARER_ID = 'sharer-uuid-1';
const RECIPIENT_ID = 'recipient-uuid-1';

function createMockShare(overrides: Partial<Share> = {}): Share {
  return {
    id: 'share-uuid-1',
    sharerId: SHARER_ID,
    recipientId: RECIPIENT_ID,
    encryptedReadKey: Buffer.from('aa'.repeat(32), 'hex'),
    encryptedWriteKey: null,
    rootNodeId: 'root-node-uuid-1',
    shareRootIpnsName: 'k51qzi5uqu5test',
    rootGeneration: '0',
    itemNameEncrypted: null,
    hiddenByRecipient: false,
    createdAt: new Date('2026-01-01'),
    updatedAt: new Date('2026-01-01'),
    ...overrides,
  } as Share;
}

function createDto(overrides: Partial<CreateShareDto> = {}): CreateShareDto {
  return {
    recipientPublicKey: BARE_PUBKEY,
    encryptedReadKey: 'aa'.repeat(32),
    rootNodeId: 'root-node-uuid-1',
    shareRootIpnsName: 'k51qzi5uqu5test',
    ...overrides,
  } as CreateShareDto;
}

describe('SharesService', () => {
  let service: SharesService;
  let shareRepo: RepoMock;
  let userRepo: RepoMock;
  let ipnsRecordRepo: RepoMock;
  let dataSource: { transaction: jest.Mock };
  let manager: {
    find: jest.Mock;
    findOne: jest.Mock;
    save: jest.Mock;
    remove: jest.Mock;
    createQueryBuilder: jest.Mock;
  };
  let queryBuilder: RepoMock;

  beforeEach(async () => {
    shareRepo = {
      findOne: jest.fn(),
      findAndCount: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      remove: jest.fn(),
    };

    userRepo = {
      findOne: jest.fn(),
    };

    // Default: caller IS the registered owner of the shared node (D-01/SC#1).
    // Individual root-ownership tests override this per-case.
    ipnsRecordRepo = {
      findOne: jest.fn().mockResolvedValue({ id: 'ipns-record-1' }),
    };

    queryBuilder = {
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      execute: jest.fn(),
    };

    manager = {
      find: jest.fn(),
      findOne: jest.fn(),
      save: jest.fn(),
      remove: jest.fn(),
      createQueryBuilder: jest.fn().mockReturnValue(queryBuilder),
    };

    dataSource = {
      transaction: jest
        .fn()
        .mockImplementation(async (cb: (m: typeof manager) => unknown) => cb(manager)),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SharesService,
        { provide: getRepositoryToken(Share), useValue: shareRepo },
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(IpnsRecord), useValue: ipnsRecordRepo },
        { provide: DataSource, useValue: dataSource },
      ],
    }).compile();

    service = module.get<SharesService>(SharesService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ===========================================================================
  // createShare()
  // ===========================================================================
  describe('createShare', () => {
    it('throws ForbiddenException when the caller did not register shareRootIpnsName in ipns_records (D-01/SC#1)', async () => {
      ipnsRecordRepo.findOne.mockResolvedValue(null);

      await expect(service.createShare(SHARER_ID, createDto())).rejects.toThrow(ForbiddenException);
      expect(ipnsRecordRepo.findOne).toHaveBeenCalledWith({
        where: { ipnsName: createDto().shareRootIpnsName, userId: SHARER_ID },
      });
      expect(shareRepo.save).not.toHaveBeenCalled();
      // Fail-fast: the root-ownership gate runs before the recipient lookup
      expect(userRepo.findOne).not.toHaveBeenCalled();
    });

    it('creates a read-only share for a valid recipient (happy path)', async () => {
      userRepo.findOne.mockResolvedValue({ id: RECIPIENT_ID, publicKey: BARE_PUBKEY });
      shareRepo.findOne.mockResolvedValue(null);
      const built = createMockShare();
      shareRepo.create.mockReturnValue(built);
      shareRepo.save.mockResolvedValue(built);

      const result = await service.createShare(SHARER_ID, createDto());

      expect(result).toBe(built);
      // Recipient looked up by bare hex pubkey
      expect(userRepo.findOne).toHaveBeenCalledWith({ where: { publicKey: BARE_PUBKEY } });
      // Read-only: encryptedWriteKey null, itemNameEncrypted null, rootGeneration defaulted
      expect(shareRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          sharerId: SHARER_ID,
          recipientId: RECIPIENT_ID,
          encryptedReadKey: Buffer.from('aa'.repeat(32), 'hex'),
          encryptedWriteKey: null,
          rootGeneration: '0',
          itemNameEncrypted: null,
          hiddenByRecipient: false,
        })
      );
      expect(shareRepo.save).toHaveBeenCalledWith(built);
    });

    it('strips a 0x prefix from the recipient public key before lookup', async () => {
      userRepo.findOne.mockResolvedValue({ id: RECIPIENT_ID, publicKey: BARE_PUBKEY });
      shareRepo.findOne.mockResolvedValue(null);
      const built = createMockShare();
      shareRepo.create.mockReturnValue(built);
      shareRepo.save.mockResolvedValue(built);

      await service.createShare(SHARER_ID, createDto({ recipientPublicKey: '0x' + BARE_PUBKEY }));

      expect(userRepo.findOne).toHaveBeenCalledWith({ where: { publicKey: BARE_PUBKEY } });
    });

    it('persists a write grant, custom generation and encrypted item name when provided', async () => {
      userRepo.findOne.mockResolvedValue({ id: RECIPIENT_ID, publicKey: BARE_PUBKEY });
      shareRepo.findOne.mockResolvedValue(null);
      const built = createMockShare();
      shareRepo.create.mockReturnValue(built);
      shareRepo.save.mockResolvedValue(built);

      await service.createShare(
        SHARER_ID,
        createDto({
          encryptedWriteKey: 'bb'.repeat(32),
          rootGeneration: '7',
          itemNameEncrypted: 'cc'.repeat(8),
        })
      );

      expect(shareRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedWriteKey: Buffer.from('bb'.repeat(32), 'hex'),
          rootGeneration: '7',
          itemNameEncrypted: Buffer.from('cc'.repeat(8), 'hex'),
        })
      );
    });

    it('throws NotFoundException when the recipient does not exist', async () => {
      userRepo.findOne.mockResolvedValue(null);

      await expect(service.createShare(SHARER_ID, createDto())).rejects.toThrow(NotFoundException);
      expect(shareRepo.create).not.toHaveBeenCalled();
    });

    it('throws ConflictException when sharing with yourself', async () => {
      userRepo.findOne.mockResolvedValue({ id: SHARER_ID, publicKey: BARE_PUBKEY });

      await expect(service.createShare(SHARER_ID, createDto())).rejects.toThrow(
        'Cannot share with yourself'
      );
      expect(shareRepo.findOne).not.toHaveBeenCalled();
    });

    it('throws ConflictException when a share already exists for the triple', async () => {
      userRepo.findOne.mockResolvedValue({ id: RECIPIENT_ID, publicKey: BARE_PUBKEY });
      shareRepo.findOne.mockResolvedValue(createMockShare());

      await expect(service.createShare(SHARER_ID, createDto())).rejects.toThrow(
        'Share already exists for this item and recipient'
      );
      expect(shareRepo.save).not.toHaveBeenCalled();
    });

    it('maps a duplicate-key DB race to ConflictException', async () => {
      userRepo.findOne.mockResolvedValue({ id: RECIPIENT_ID, publicKey: BARE_PUBKEY });
      shareRepo.findOne.mockResolvedValue(null);
      shareRepo.create.mockReturnValue(createMockShare());
      // Postgres surfaces a unique violation as SQLSTATE 23505; the service maps
      // on the error code, not a brittle message substring.
      const dupErr = Object.assign(new Error('duplicate key value violates unique constraint'), {
        code: '23505',
      });
      shareRepo.save.mockRejectedValue(dupErr);

      await expect(service.createShare(SHARER_ID, createDto())).rejects.toThrow(ConflictException);
    });

    it('rethrows non-duplicate save errors unchanged', async () => {
      userRepo.findOne.mockResolvedValue({ id: RECIPIENT_ID, publicKey: BARE_PUBKEY });
      shareRepo.findOne.mockResolvedValue(null);
      shareRepo.create.mockReturnValue(createMockShare());
      shareRepo.save.mockRejectedValue(new Error('connection terminated'));

      await expect(service.createShare(SHARER_ID, createDto())).rejects.toThrow(
        'connection terminated'
      );
    });
  });

  // ===========================================================================
  // getReceivedShares()
  // ===========================================================================
  describe('getReceivedShares', () => {
    it('returns non-hidden received shares with total, paginated', async () => {
      const shares = [createMockShare()];
      shareRepo.findAndCount.mockResolvedValue([shares, 1]);

      const result = await service.getReceivedShares(RECIPIENT_ID, 10, 20);

      expect(result).toEqual({ shares, total: 1 });
      expect(shareRepo.findAndCount).toHaveBeenCalledWith({
        where: { recipientId: RECIPIENT_ID, hiddenByRecipient: false },
        relations: ['sharer'],
        order: { createdAt: 'DESC' },
        take: 10,
        skip: 20,
      });
    });
  });

  // ===========================================================================
  // getSentShares()
  // ===========================================================================
  describe('getSentShares', () => {
    it('returns sent shares with total, paginated', async () => {
      const shares = [createMockShare(), createMockShare({ id: 'share-uuid-2' })];
      shareRepo.findAndCount.mockResolvedValue([shares, 2]);

      const result = await service.getSentShares(SHARER_ID, 5, 0);

      expect(result).toEqual({ shares, total: 2 });
      expect(shareRepo.findAndCount).toHaveBeenCalledWith({
        where: { sharerId: SHARER_ID },
        relations: ['recipient'],
        order: { createdAt: 'DESC' },
        take: 5,
        skip: 0,
      });
    });
  });

  // ===========================================================================
  // revokeShare()
  // ===========================================================================
  describe('revokeShare', () => {
    it('hard-deletes the share when the caller is the sharer', async () => {
      const share = createMockShare();
      shareRepo.findOne.mockResolvedValue(share);

      await service.revokeShare('share-uuid-1', SHARER_ID);

      expect(shareRepo.remove).toHaveBeenCalledWith(share);
    });

    it('throws NotFoundException when the share is missing', async () => {
      shareRepo.findOne.mockResolvedValue(null);

      await expect(service.revokeShare('missing', SHARER_ID)).rejects.toThrow(NotFoundException);
      expect(shareRepo.remove).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException when a non-sharer attempts to revoke', async () => {
      shareRepo.findOne.mockResolvedValue(createMockShare());

      await expect(service.revokeShare('share-uuid-1', 'someone-else')).rejects.toThrow(
        ForbiddenException
      );
      expect(shareRepo.remove).not.toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // revokeForItems()
  // ===========================================================================
  describe('revokeForItems', () => {
    it('returns zero counts and skips the transaction for an empty name list', async () => {
      const result = await service.revokeForItems(SHARER_ID, []);

      expect(result).toEqual({ revokedShares: 0, revokedInvites: 0 });
      expect(dataSource.transaction).not.toHaveBeenCalled();
    });

    it('hard-deletes matching shares and revokes active invites in a transaction', async () => {
      const shares = [createMockShare(), createMockShare({ id: 'share-uuid-2' })];
      manager.find.mockResolvedValue(shares);
      queryBuilder.execute.mockResolvedValue({ affected: 3 });

      const result = await service.revokeForItems(SHARER_ID, ['k51a', 'k51b', 'k51a']);

      expect(result).toEqual({ revokedShares: 2, revokedInvites: 3 });
      // De-duped names threaded into both the share query and the invite update
      expect(manager.find).toHaveBeenCalledWith(Share, {
        where: { sharerId: SHARER_ID, shareRootIpnsName: In(['k51a', 'k51b']) },
      });
      expect(manager.remove).toHaveBeenCalledWith(shares);
      expect(queryBuilder.update).toHaveBeenCalledWith(ShareInvite);
      expect(queryBuilder.set).toHaveBeenCalledWith({ status: 'revoked' });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('status = :status', { status: 'active' });
    });

    it('skips manager.remove when no shares match but still revokes invites', async () => {
      manager.find.mockResolvedValue([]);
      queryBuilder.execute.mockResolvedValue({ affected: 1 });

      const result = await service.revokeForItems(SHARER_ID, ['k51a']);

      expect(result).toEqual({ revokedShares: 0, revokedInvites: 1 });
      expect(manager.remove).not.toHaveBeenCalled();
    });

    it('treats an undefined affected count as zero revoked invites', async () => {
      manager.find.mockResolvedValue([]);
      queryBuilder.execute.mockResolvedValue({});

      const result = await service.revokeForItems(SHARER_ID, ['k51a']);

      expect(result).toEqual({ revokedShares: 0, revokedInvites: 0 });
    });
  });

  // ===========================================================================
  // hideShare()
  // ===========================================================================
  describe('hideShare', () => {
    it('sets hiddenByRecipient and saves when the caller is the recipient', async () => {
      const share = createMockShare({ hiddenByRecipient: false });
      shareRepo.findOne.mockResolvedValue(share);

      await service.hideShare('share-uuid-1', RECIPIENT_ID);

      expect(share.hiddenByRecipient).toBe(true);
      expect(shareRepo.save).toHaveBeenCalledWith(share);
    });

    it('throws NotFoundException when the share is missing', async () => {
      shareRepo.findOne.mockResolvedValue(null);

      await expect(service.hideShare('missing', RECIPIENT_ID)).rejects.toThrow(NotFoundException);
      expect(shareRepo.save).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException when a non-recipient attempts to hide', async () => {
      shareRepo.findOne.mockResolvedValue(createMockShare());

      await expect(service.hideShare('share-uuid-1', 'not-the-recipient')).rejects.toThrow(
        ForbiddenException
      );
      expect(shareRepo.save).not.toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // lookupUserByPublicKey()
  // ===========================================================================
  describe('lookupUserByPublicKey', () => {
    it('returns true when a user exists for the bare pubkey', async () => {
      userRepo.findOne.mockResolvedValue({ id: RECIPIENT_ID });

      const result = await service.lookupUserByPublicKey(BARE_PUBKEY);

      expect(result).toBe(true);
      expect(userRepo.findOne).toHaveBeenCalledWith({
        where: { publicKey: BARE_PUBKEY },
        select: ['id'],
      });
    });

    it('strips a 0x prefix before lookup and returns false when absent', async () => {
      userRepo.findOne.mockResolvedValue(null);

      const result = await service.lookupUserByPublicKey('0x' + BARE_PUBKEY);

      expect(result).toBe(false);
      expect(userRepo.findOne).toHaveBeenCalledWith({
        where: { publicKey: BARE_PUBKEY },
        select: ['id'],
      });
    });
  });

  describe('updateGrant', () => {
    it('persists the rotated key and advances rootGeneration for the sharer', async () => {
      const share = createMockShare({ rootGeneration: '2' });
      manager.findOne.mockResolvedValue(share);

      await service.updateGrant('share-uuid-1', SHARER_ID, 'bb'.repeat(32), '3');

      expect(manager.findOne).toHaveBeenCalledWith(Share, {
        where: { id: 'share-uuid-1' },
        lock: { mode: 'pessimistic_write' },
      });
      expect(share.encryptedReadKey).toEqual(Buffer.from('bb'.repeat(32), 'hex'));
      expect(share.rootGeneration).toBe('3');
      expect(manager.save).toHaveBeenCalledWith(share);
    });

    it('accepts an equal rootGeneration (idempotent re-mint retry)', async () => {
      const share = createMockShare({ rootGeneration: '3' });
      manager.findOne.mockResolvedValue(share);

      await service.updateGrant('share-uuid-1', SHARER_ID, 'bb'.repeat(32), '3');

      expect(manager.save).toHaveBeenCalledWith(share);
    });

    it('throws ConflictException when rootGeneration regresses below the stored value', async () => {
      manager.findOne.mockResolvedValue(createMockShare({ rootGeneration: '5' }));

      await expect(
        service.updateGrant('share-uuid-1', SHARER_ID, 'bb'.repeat(32), '4')
      ).rejects.toThrow(ConflictException);
      expect(manager.save).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the share is missing', async () => {
      manager.findOne.mockResolvedValue(null);

      await expect(service.updateGrant('missing', SHARER_ID, 'bb'.repeat(32), '1')).rejects.toThrow(
        NotFoundException
      );
      expect(manager.save).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException when a non-sharer attempts the update', async () => {
      manager.findOne.mockResolvedValue(createMockShare());

      await expect(
        service.updateGrant('share-uuid-1', 'not-the-sharer', 'bb'.repeat(32), '1')
      ).rejects.toThrow(ForbiddenException);
      expect(manager.save).not.toHaveBeenCalled();
    });

    it('leaves encryptedWriteKey unchanged when neither encryptedWriteKey nor clearEncryptedWriteKey is supplied (read-only rotation, T-68.1-19-02)', async () => {
      const existingWrite = Buffer.from('cc'.repeat(32), 'hex');
      const share = createMockShare({ rootGeneration: '2', encryptedWriteKey: existingWrite });
      manager.findOne.mockResolvedValue(share);

      await service.updateGrant('share-uuid-1', SHARER_ID, 'bb'.repeat(32), '3');

      expect(share.encryptedWriteKey).toBe(existingWrite);
      expect(manager.save).toHaveBeenCalledWith(share);
    });

    it('sets encryptedWriteKey when supplied (read->write upgrade)', async () => {
      const share = createMockShare({ rootGeneration: '2', encryptedWriteKey: null });
      manager.findOne.mockResolvedValue(share);

      await service.updateGrant('share-uuid-1', SHARER_ID, 'bb'.repeat(32), '3', 'dd'.repeat(32));

      expect(share.encryptedWriteKey).toEqual(Buffer.from('dd'.repeat(32), 'hex'));
      expect(manager.save).toHaveBeenCalledWith(share);
    });

    it('clears encryptedWriteKey to null when clearEncryptedWriteKey is true (write->read downgrade)', async () => {
      const share = createMockShare({
        rootGeneration: '2',
        encryptedWriteKey: Buffer.from('cc'.repeat(32), 'hex'),
      });
      manager.findOne.mockResolvedValue(share);

      await service.updateGrant('share-uuid-1', SHARER_ID, 'bb'.repeat(32), '3', undefined, true);

      expect(share.encryptedWriteKey).toBeNull();
      expect(manager.save).toHaveBeenCalledWith(share);
    });

    it('throws BadRequestException when both encryptedWriteKey and clearEncryptedWriteKey are supplied', async () => {
      await expect(
        service.updateGrant('share-uuid-1', SHARER_ID, 'bb'.repeat(32), '3', 'dd'.repeat(32), true)
      ).rejects.toThrow(BadRequestException);
      expect(manager.findOne).not.toHaveBeenCalled();
      expect(manager.save).not.toHaveBeenCalled();
    });
  });
});
