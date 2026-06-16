import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { ShareInviteService } from './share-invite.service';
import { ShareInvite } from './entities/share-invite.entity';
import { ShareKey } from './entities/share-key.entity';
import { CreateInviteDto } from './dto/create-invite.dto';
import { ClaimInviteDto } from './dto/claim-invite.dto';

describe('ShareInviteService', () => {
  let service: ShareInviteService;
  let mockInviteRepo: {
    findOne: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    remove: jest.Mock;
  };
  let mockDataSource: { transaction: jest.Mock };

  const sharerId = '550e8400-e29b-41d4-a716-446655440000';
  const claimerId = '660e8400-e29b-41d4-a716-446655440001';
  const inviteId = '770e8400-e29b-41d4-a716-446655440002';
  const testToken = 'abc123-token';
  const testIpnsName = 'k51qzi5uqu5dg12345';
  const testEncryptedKey = 'cc'.repeat(130);

  const futureDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const pastDate = new Date(Date.now() - 1000);

  const activeInvite: ShareInvite = {
    id: inviteId,
    token: testToken,
    sharerId,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    sharer: {} as any,
    itemType: 'folder',
    ipnsName: testIpnsName,
    itemName: 'Shared Folder',
    encryptedKey: Buffer.from(testEncryptedKey, 'hex'),
    encryptedChildKeys: null,
    status: 'active',
    maxClaims: 1,
    claimCount: 0,
    claimedBy: null,
    expiresAt: futureDate,
    createdAt: new Date('2026-02-20T12:00:00Z'),
  };

  const createDto: CreateInviteDto = {
    itemType: 'folder',
    ipnsName: testIpnsName,
    itemName: 'Shared Folder',
    encryptedKey: testEncryptedKey,
  };

  const claimDto: ClaimInviteDto = {
    encryptedKey: 'dd'.repeat(130),
  };

  beforeEach(async () => {
    mockInviteRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      create: jest.fn().mockImplementation((data) => ({ ...data })),
      save: jest.fn().mockImplementation((entity) => Promise.resolve({ id: inviteId, ...entity })),
      remove: jest.fn().mockResolvedValue(undefined),
    };

    mockDataSource = {
      transaction: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ShareInviteService,
        {
          provide: getRepositoryToken(ShareInvite),
          useValue: mockInviteRepo,
        },
        {
          provide: DataSource,
          useValue: mockDataSource,
        },
      ],
    }).compile();

    service = module.get<ShareInviteService>(ShareInviteService);
  });

  describe('createInvite', () => {
    it('should create an invite with token and 7-day expiry', async () => {
      const result = await service.createInvite(sharerId, createDto);

      expect(mockInviteRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          sharerId,
          itemType: 'folder',
          ipnsName: testIpnsName,
          itemName: 'Shared Folder',
          status: 'active',
          maxClaims: 1,
          claimCount: 0,
        })
      );
      expect(mockInviteRepo.save).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it('should generate a base64url token', async () => {
      await service.createInvite(sharerId, createDto);

      const createCall = mockInviteRepo.create.mock.calls[0][0];
      expect(createCall.token).toBeDefined();
      expect(typeof createCall.token).toBe('string');
      expect(createCall.token.length).toBeGreaterThan(0);
    });

    it('should set expiry ~7 days in the future', async () => {
      const before = Date.now();
      await service.createInvite(sharerId, createDto);
      const after = Date.now();

      const createCall = mockInviteRepo.create.mock.calls[0][0];
      const expiresAt = createCall.expiresAt.getTime();
      const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
      expect(expiresAt).toBeGreaterThanOrEqual(before + sevenDaysMs - 100);
      expect(expiresAt).toBeLessThanOrEqual(after + sevenDaysMs + 100);
    });

    it('should convert encryptedKey from hex to Buffer', async () => {
      await service.createInvite(sharerId, createDto);

      const createCall = mockInviteRepo.create.mock.calls[0][0];
      expect(Buffer.isBuffer(createCall.encryptedKey)).toBe(true);
    });

    it('should pass through encryptedChildKeys when provided', async () => {
      const dtoWithChildren: CreateInviteDto = {
        ...createDto,
        encryptedChildKeys: [
          {
            keyType: 'file',
            itemId: '880e8400-e29b-41d4-a716-446655440003',
            encryptedKey: 'ee'.repeat(130),
          },
        ],
      };

      await service.createInvite(sharerId, dtoWithChildren);

      const createCall = mockInviteRepo.create.mock.calls[0][0];
      expect(createCall.encryptedChildKeys).toEqual(dtoWithChildren.encryptedChildKeys);
    });

    it('should set encryptedChildKeys to null when not provided', async () => {
      await service.createInvite(sharerId, createDto);

      const createCall = mockInviteRepo.create.mock.calls[0][0];
      expect(createCall.encryptedChildKeys).toBeNull();
    });

    it('should persist itemNameEncrypted ciphertext as Buffer and never encrypt server-side', async () => {
      const hexCiphertext = 'ab'.repeat(80);
      const dtoWithEncryptedName: CreateInviteDto = {
        ...createDto,
        itemNameEncrypted: hexCiphertext,
      };

      await service.createInvite(sharerId, dtoWithEncryptedName);

      const createCall = mockInviteRepo.create.mock.calls[0][0];
      expect(Buffer.isBuffer(createCall.itemNameEncrypted)).toBe(true);
      expect(createCall.itemNameEncrypted).toEqual(Buffer.from(hexCiphertext, 'hex'));
    });

    it('should persist null itemNameEncrypted for legacy plaintext clients', async () => {
      // createDto has no itemNameEncrypted field
      await service.createInvite(sharerId, createDto);

      const createCall = mockInviteRepo.create.mock.calls[0][0];
      expect(createCall.itemNameEncrypted).toBeNull();
    });
  });

  describe('getInviteStatus', () => {
    it('should return status for an active invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue(activeInvite);

      const result = await service.getInviteStatus(testToken);

      expect(result).toEqual({ status: 'active' });
    });

    it('should return null when invite not found', async () => {
      mockInviteRepo.findOne.mockResolvedValue(null);

      const result = await service.getInviteStatus('nonexistent');

      expect(result).toBeNull();
    });

    it('should auto-expire and delete past-expiry invites', async () => {
      const expiredInvite = { ...activeInvite, expiresAt: pastDate };
      mockInviteRepo.findOne.mockResolvedValue(expiredInvite);

      const result = await service.getInviteStatus(testToken);

      expect(result).toBeNull();
      expect(mockInviteRepo.remove).toHaveBeenCalledWith(expiredInvite);
    });

    it('should return status for claimed invite without auto-expiring', async () => {
      const claimedInvite = { ...activeInvite, status: 'claimed' as const, expiresAt: pastDate };
      mockInviteRepo.findOne.mockResolvedValue(claimedInvite);

      const result = await service.getInviteStatus(testToken);

      expect(result).toEqual({ status: 'claimed' });
      expect(mockInviteRepo.remove).not.toHaveBeenCalled();
    });
  });

  describe('getInviteForClaim', () => {
    it('should return full invite for active, non-expired invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue(activeInvite);

      const result = await service.getInviteForClaim(testToken);

      expect(result).toEqual(activeInvite);
    });

    it('should return null when invite not found', async () => {
      mockInviteRepo.findOne.mockResolvedValue(null);

      const result = await service.getInviteForClaim('nonexistent');

      expect(result).toBeNull();
    });

    it('should auto-expire and return null for past-expiry active invite', async () => {
      const expiredInvite = { ...activeInvite, expiresAt: pastDate };
      mockInviteRepo.findOne.mockResolvedValue(expiredInvite);

      const result = await service.getInviteForClaim(testToken);

      expect(result).toBeNull();
      expect(mockInviteRepo.remove).toHaveBeenCalledWith(expiredInvite);
    });

    it('should return null for non-active invite', async () => {
      const claimedInvite = { ...activeInvite, status: 'claimed' as const };
      mockInviteRepo.findOne.mockResolvedValue(claimedInvite);

      const result = await service.getInviteForClaim(testToken);

      expect(result).toBeNull();
    });

    it('should return null for revoked invite', async () => {
      const revokedInvite = { ...activeInvite, status: 'revoked' as const };
      mockInviteRepo.findOne.mockResolvedValue(revokedInvite);

      const result = await service.getInviteForClaim(testToken);

      expect(result).toBeNull();
    });
  });

  describe('claimInvite', () => {
    let mockManager: {
      createQueryBuilder: jest.Mock;
      findOne: jest.Mock;
      find: jest.Mock;
      create: jest.Mock;
      save: jest.Mock;
      remove: jest.Mock;
    };
    let mockQb: {
      update: jest.Mock;
      set: jest.Mock;
      where: jest.Mock;
      andWhere: jest.Mock;
      execute: jest.Mock;
    };

    beforeEach(() => {
      mockQb = {
        update: jest.fn().mockReturnThis(),
        set: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 1 }),
      };

      mockManager = {
        createQueryBuilder: jest.fn().mockReturnValue(mockQb),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
        create: jest.fn().mockImplementation((_, data) => ({ ...data })),
        save: jest.fn().mockImplementation((entity) => {
          if (Array.isArray(entity)) return Promise.resolve(entity);
          return Promise.resolve({ id: 'new-share-id', ...entity });
        }),
        remove: jest.fn().mockResolvedValue(undefined),
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mockDataSource.transaction.mockImplementation((cb: any) => cb(mockManager));
      mockInviteRepo.findOne.mockResolvedValue(activeInvite);
    });

    it('should claim an active invite and create Share record', async () => {
      const result = await service.claimInvite(testToken, claimerId, claimDto);

      expect(result).toEqual({ shareId: 'new-share-id' });
      expect(mockQb.execute).toHaveBeenCalled();
      expect(mockManager.save).toHaveBeenCalled();
    });

    it('should throw NotFoundException when invite not found', async () => {
      mockInviteRepo.findOne.mockResolvedValue(null);

      await expect(service.claimInvite('nonexistent', claimerId, claimDto)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should throw NotFoundException for expired invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue({
        ...activeInvite,
        expiresAt: pastDate,
      });

      await expect(service.claimInvite(testToken, claimerId, claimDto)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should delete expired active invite before throwing', async () => {
      mockInviteRepo.findOne.mockResolvedValue({
        ...activeInvite,
        expiresAt: pastDate,
      });

      await expect(service.claimInvite(testToken, claimerId, claimDto)).rejects.toThrow(
        NotFoundException
      );
      expect(mockInviteRepo.remove).toHaveBeenCalled();
    });

    it('should not delete expired non-active invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue({
        ...activeInvite,
        status: 'revoked' as const,
        expiresAt: pastDate,
      });

      await expect(service.claimInvite(testToken, claimerId, claimDto)).rejects.toThrow(
        NotFoundException
      );
      expect(mockInviteRepo.remove).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException for non-active invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue({
        ...activeInvite,
        status: 'claimed' as const,
      });

      await expect(service.claimInvite(testToken, claimerId, claimDto)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should throw ConflictException for self-claim', async () => {
      await expect(service.claimInvite(testToken, sharerId, claimDto)).rejects.toThrow(
        ConflictException
      );
    });

    it('should throw ConflictException when atomic UPDATE affects 0 rows', async () => {
      mockQb.execute.mockResolvedValue({ affected: 0 });

      await expect(service.claimInvite(testToken, claimerId, claimDto)).rejects.toThrow(
        ConflictException
      );
    });

    it('should return existing share if one already exists', async () => {
      const existingShare = { id: 'existing-share-id' };
      mockManager.findOne.mockResolvedValue(existingShare);

      const result = await service.claimInvite(testToken, claimerId, claimDto);

      expect(result).toEqual({ shareId: 'existing-share-id' });
    });

    it('should clean up revoked shares before creating new one', async () => {
      const revokedShares = [{ id: 'revoked-1' }, { id: 'revoked-2' }];
      mockManager.findOne.mockResolvedValue(null); // no existing active share
      mockManager.find.mockResolvedValue(revokedShares);

      await service.claimInvite(testToken, claimerId, claimDto);

      expect(mockManager.remove).toHaveBeenCalledWith(revokedShares);
    });

    it('should create ShareKey records when childKeys provided', async () => {
      const dtoWithChildren: ClaimInviteDto = {
        encryptedKey: 'dd'.repeat(130),
        childKeys: [
          {
            keyType: 'file',
            itemId: '880e8400-e29b-41d4-a716-446655440003',
            encryptedKey: 'ee'.repeat(130),
          },
          {
            keyType: 'folder',
            itemId: '990e8400-e29b-41d4-a716-446655440004',
            encryptedKey: 'ff'.repeat(130),
          },
        ],
      };

      await service.claimInvite(testToken, claimerId, dtoWithChildren);

      // save called for Share + ShareKeys
      expect(mockManager.save).toHaveBeenCalledTimes(2);
      expect(mockManager.create).toHaveBeenCalledWith(
        ShareKey,
        expect.objectContaining({ keyType: 'file' })
      );
      expect(mockManager.create).toHaveBeenCalledWith(
        ShareKey,
        expect.objectContaining({ keyType: 'folder' })
      );
    });

    it('should persist itemNameEncrypted from claim DTO onto the created Share as Buffer', async () => {
      const hexCiphertext = 'ab'.repeat(80);
      const dtoWithEncryptedName: ClaimInviteDto = {
        encryptedKey: 'dd'.repeat(130),
        itemNameEncrypted: hexCiphertext,
      };

      await service.claimInvite(testToken, claimerId, dtoWithEncryptedName);

      const shareCreateCall =
        mockManager.create.mock.calls.find((call) => call[0] && call[0].name === 'Share') ??
        mockManager.create.mock.calls[0];
      const shareData = shareCreateCall[1] ?? shareCreateCall[0];
      expect(Buffer.isBuffer(shareData.itemNameEncrypted)).toBe(true);
      expect(shareData.itemNameEncrypted).toEqual(Buffer.from(hexCiphertext, 'hex'));
    });

    it('should not create ShareKey records when childKeys empty', async () => {
      const dtoNoChildren: ClaimInviteDto = {
        encryptedKey: 'dd'.repeat(130),
        childKeys: [],
      };

      await service.claimInvite(testToken, claimerId, dtoNoChildren);

      // save called only once for the Share
      expect(mockManager.save).toHaveBeenCalledTimes(1);
    });
  });

  describe('getInvitesForItem', () => {
    it('should return active, non-expired invites', async () => {
      const invites = [activeInvite];
      mockInviteRepo.find.mockResolvedValue(invites);

      const result = await service.getInvitesForItem(sharerId, testIpnsName);

      expect(result).toEqual(invites);
    });

    it('should auto-clean expired invites', async () => {
      const expired = { ...activeInvite, id: 'expired-1', expiresAt: pastDate };
      const active = { ...activeInvite, id: 'active-1', expiresAt: futureDate };
      mockInviteRepo.find.mockResolvedValue([expired, active]);

      const result = await service.getInvitesForItem(sharerId, testIpnsName);

      expect(result).toEqual([active]);
      expect(mockInviteRepo.remove).toHaveBeenCalledWith([expired]);
    });

    it('should not call remove when no invites expired', async () => {
      mockInviteRepo.find.mockResolvedValue([activeInvite]);

      await service.getInvitesForItem(sharerId, testIpnsName);

      expect(mockInviteRepo.remove).not.toHaveBeenCalled();
    });

    it('should return empty array when no active invites', async () => {
      mockInviteRepo.find.mockResolvedValue([]);

      const result = await service.getInvitesForItem(sharerId, testIpnsName);

      expect(result).toEqual([]);
    });
  });

  describe('revokeInvite', () => {
    it('should set invite status to revoked', async () => {
      mockInviteRepo.findOne.mockResolvedValue({ ...activeInvite });

      await service.revokeInvite(inviteId, sharerId);

      expect(mockInviteRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'revoked' })
      );
    });

    it('should throw NotFoundException when invite not found', async () => {
      mockInviteRepo.findOne.mockResolvedValue(null);

      await expect(service.revokeInvite('nonexistent', sharerId)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should throw ForbiddenException when non-sharer revokes', async () => {
      mockInviteRepo.findOne.mockResolvedValue(activeInvite);

      await expect(service.revokeInvite(inviteId, claimerId)).rejects.toThrow(ForbiddenException);
    });
  });
});
