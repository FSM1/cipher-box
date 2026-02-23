import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { SharesService } from './shares.service';
import { Share } from './entities/share.entity';
import { ShareKey } from './entities/share-key.entity';
import { ShareInvite } from './entities/share-invite.entity';
import { User } from '../auth/entities/user.entity';
import { CreateShareDto } from './dto/create-share.dto';
import { AddShareKeysDto } from './dto/share-key.dto';

describe('SharesService', () => {
  let service: SharesService;
  let mockShareRepo: {
    findOne: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    remove: jest.Mock;
  };
  let mockShareKeyRepo: {
    findOne: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
  };
  let mockShareInviteRepo: {
    findOne: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    remove: jest.Mock;
    createQueryBuilder: jest.Mock;
  };
  let mockUserRepo: {
    findOne: jest.Mock;
  };

  // Test data
  const sharerId = '550e8400-e29b-41d4-a716-446655440000';
  const recipientId = '660e8400-e29b-41d4-a716-446655440001';
  const shareId = '770e8400-e29b-41d4-a716-446655440002';
  const recipientPublicKey = '04' + 'ab'.repeat(64);
  const testEncryptedKey = 'cc'.repeat(64);
  const testIpnsName = 'k51qzi5uqu5dg12345';

  const mockRecipient = { id: recipientId, publicKey: recipientPublicKey } as User;

  const mockShare: Share = {
    id: shareId,
    sharerId,
    recipientId,
    itemType: 'folder',
    ipnsName: testIpnsName,
    itemName: 'My Folder',
    encryptedKey: Buffer.from(testEncryptedKey, 'hex'),
    hiddenByRecipient: false,
    revokedAt: null,
    shareKeys: [],
    sharer: {} as User,
    recipient: mockRecipient,
    createdAt: new Date('2026-02-20T12:00:00Z'),
    updatedAt: new Date('2026-02-20T12:00:00Z'),
  };

  const testCreateDto: CreateShareDto = {
    recipientPublicKey,
    itemType: 'folder',
    ipnsName: testIpnsName,
    itemName: 'My Folder',
    encryptedKey: testEncryptedKey,
  };

  beforeEach(async () => {
    mockShareRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      remove: jest.fn(),
    };
    mockShareKeyRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
    };
    mockShareInviteRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      create: jest.fn().mockImplementation((data) => data),
      save: jest.fn(),
      remove: jest.fn(),
      createQueryBuilder: jest.fn(),
    };
    mockUserRepo = {
      findOne: jest.fn(),
    };

    const mockDataSource = {
      transaction: jest.fn().mockImplementation((cb: (manager: unknown) => Promise<unknown>) =>
        cb({
          createQueryBuilder: mockShareInviteRepo.createQueryBuilder,
          findOne: (entity: unknown, opts: unknown) =>
            entity === Share ? mockShareRepo.findOne(opts) : mockShareInviteRepo.findOne(opts),
          find: (entity: unknown, opts: unknown) =>
            entity === Share ? mockShareRepo.find(opts) : mockShareInviteRepo.find(opts),
          create: (entity: unknown, data: unknown) =>
            entity === ShareKey ? mockShareKeyRepo.create(data) : mockShareRepo.create(data),
          save: (data: unknown) => {
            if (Array.isArray(data)) return mockShareKeyRepo.save(data);
            return mockShareRepo.save(data);
          },
          remove: (data: unknown) => mockShareRepo.remove(data),
        })
      ),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SharesService,
        { provide: getRepositoryToken(Share), useValue: mockShareRepo },
        { provide: getRepositoryToken(ShareKey), useValue: mockShareKeyRepo },
        { provide: getRepositoryToken(ShareInvite), useValue: mockShareInviteRepo },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: DataSource, useValue: mockDataSource },
      ],
    }).compile();

    service = module.get<SharesService>(SharesService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createShare', () => {
    it('should create a share for a valid recipient', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null); // no existing active share
      mockShareRepo.find.mockResolvedValue([]); // no revoked shares
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);

      const result = await service.createShare(sharerId, testCreateDto);

      expect(result.id).toBe(shareId);
      expect(mockUserRepo.findOne).toHaveBeenCalledWith({
        where: { publicKey: recipientPublicKey },
      });
      expect(mockShareRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          sharerId,
          recipientId,
          itemType: 'folder',
          ipnsName: testIpnsName,
          itemName: 'My Folder',
        })
      );
    });

    it('should store encryptedKey as Buffer from hex', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]);
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);

      await service.createShare(sharerId, testCreateDto);

      const createCall = mockShareRepo.create.mock.calls[0][0];
      expect(Buffer.isBuffer(createCall.encryptedKey)).toBe(true);
      expect(createCall.encryptedKey.toString('hex')).toBe(testEncryptedKey);
    });

    it('should create child keys when provided', async () => {
      const dtoWithChildren: CreateShareDto = {
        ...testCreateDto,
        childKeys: [
          {
            keyType: 'file',
            itemId: '880e8400-e29b-41d4-a716-446655440003',
            encryptedKey: 'dd'.repeat(32),
          },
          {
            keyType: 'folder',
            itemId: '990e8400-e29b-41d4-a716-446655440004',
            encryptedKey: 'ee'.repeat(32),
          },
        ],
      };

      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]);
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);
      mockShareKeyRepo.create.mockImplementation((data) => data);
      mockShareKeyRepo.save.mockResolvedValue([]);

      await service.createShare(sharerId, dtoWithChildren);

      expect(mockShareKeyRepo.create).toHaveBeenCalledTimes(2);
      expect(mockShareKeyRepo.save).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ keyType: 'file', shareId }),
          expect.objectContaining({ keyType: 'folder', shareId }),
        ])
      );
    });

    it('should skip child key creation when childKeys is empty', async () => {
      const dtoNoChildren: CreateShareDto = { ...testCreateDto, childKeys: [] };

      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]);
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);

      await service.createShare(sharerId, dtoNoChildren);

      expect(mockShareKeyRepo.create).not.toHaveBeenCalled();
      expect(mockShareKeyRepo.save).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException when recipient not found', async () => {
      mockUserRepo.findOne.mockResolvedValue(null);

      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(NotFoundException);
      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(
        'Recipient not found'
      );
    });

    it('should throw ConflictException for self-share', async () => {
      const selfUser = { id: sharerId, publicKey: recipientPublicKey } as User;
      mockUserRepo.findOne.mockResolvedValue(selfUser);

      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(ConflictException);
      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(
        'Cannot share with yourself'
      );
    });

    it('should throw ConflictException for duplicate active share', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(mockShare); // existing active share

      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(ConflictException);
      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(
        'Share already exists for this item and recipient'
      );
    });

    it('should clean up revoked records before creating new share', async () => {
      const revokedShare = { ...mockShare, revokedAt: new Date() };
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null); // no active share
      mockShareRepo.find.mockResolvedValue([revokedShare]); // one revoked share
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);

      await service.createShare(sharerId, testCreateDto);

      expect(mockShareRepo.remove).toHaveBeenCalledWith([revokedShare]);
    });

    it('should not call remove when no revoked records exist', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]); // no revoked shares
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);

      await service.createShare(sharerId, testCreateDto);

      expect(mockShareRepo.remove).not.toHaveBeenCalled();
    });

    it('should strip 0x prefix from recipientPublicKey before lookup', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]);
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);

      const dto = { ...testCreateDto, recipientPublicKey: '0x' + recipientPublicKey };
      await service.createShare(sharerId, dto);

      expect(mockUserRepo.findOne).toHaveBeenCalledWith({
        where: { publicKey: recipientPublicKey },
      });
    });

    it('should accept recipientPublicKey without 0x prefix', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]);
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockResolvedValue(mockShare);

      // Key without 0x prefix -- should be used as-is
      const dto = { ...testCreateDto, recipientPublicKey };
      await service.createShare(sharerId, dto);

      expect(mockUserRepo.findOne).toHaveBeenCalledWith({
        where: { publicKey: recipientPublicKey },
      });
    });

    it('should throw ConflictException on duplicate key race condition', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]);
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockRejectedValue(
        new Error('duplicate key value violates unique constraint')
      );

      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(ConflictException);
      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(
        'Share already exists for this item and recipient'
      );
    });

    it('should rethrow non-duplicate-key save errors', async () => {
      mockUserRepo.findOne.mockResolvedValue(mockRecipient);
      mockShareRepo.findOne.mockResolvedValue(null);
      mockShareRepo.find.mockResolvedValue([]);
      mockShareRepo.create.mockReturnValue(mockShare);
      mockShareRepo.save.mockRejectedValue(new Error('connection failed'));

      await expect(service.createShare(sharerId, testCreateDto)).rejects.toThrow(
        'connection failed'
      );
    });
  });

  describe('getReceivedShares', () => {
    it('should return active non-hidden shares with sharer relation', async () => {
      const shares = [mockShare];
      mockShareRepo.find.mockResolvedValue(shares);

      const result = await service.getReceivedShares(recipientId);

      expect(result).toEqual(shares);
      expect(mockShareRepo.find).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            recipientId,
            hiddenByRecipient: false,
          }),
          relations: ['sharer'],
          order: { createdAt: 'DESC' },
        })
      );
    });

    it('should return empty array when no shares exist', async () => {
      mockShareRepo.find.mockResolvedValue([]);

      const result = await service.getReceivedShares(recipientId);

      expect(result).toEqual([]);
    });
  });

  describe('getSentShares', () => {
    it('should return active shares with recipient relation', async () => {
      const shares = [mockShare];
      mockShareRepo.find.mockResolvedValue(shares);

      const result = await service.getSentShares(sharerId);

      expect(result).toEqual(shares);
      expect(mockShareRepo.find).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ sharerId }),
          relations: ['recipient'],
          order: { createdAt: 'DESC' },
        })
      );
    });
  });

  describe('getShareKeys', () => {
    it('should return keys when user is sharer', async () => {
      const mockKeys = [
        {
          id: 'k1',
          shareId,
          keyType: 'file',
          itemId: 'f1',
          encryptedKey: Buffer.from('aa', 'hex'),
          createdAt: new Date(),
        },
      ] as ShareKey[];
      mockShareRepo.findOne.mockResolvedValue(mockShare);
      mockShareKeyRepo.find.mockResolvedValue(mockKeys);

      const result = await service.getShareKeys(shareId, sharerId);

      expect(result).toEqual(mockKeys);
    });

    it('should return keys when user is recipient', async () => {
      const mockKeys = [] as ShareKey[];
      mockShareRepo.findOne.mockResolvedValue(mockShare);
      mockShareKeyRepo.find.mockResolvedValue(mockKeys);

      const result = await service.getShareKeys(shareId, recipientId);

      expect(result).toEqual(mockKeys);
    });

    it('should throw NotFoundException when share not found', async () => {
      mockShareRepo.findOne.mockResolvedValue(null);

      await expect(service.getShareKeys(shareId, sharerId)).rejects.toThrow(NotFoundException);
      await expect(service.getShareKeys(shareId, sharerId)).rejects.toThrow('Share not found');
    });

    it('should throw ForbiddenException for unauthorized user', async () => {
      mockShareRepo.findOne.mockResolvedValue(mockShare);
      const otherId = 'aa0e8400-e29b-41d4-a716-446655440099';

      await expect(service.getShareKeys(shareId, otherId)).rejects.toThrow(ForbiddenException);
      await expect(service.getShareKeys(shareId, otherId)).rejects.toThrow(
        'Not authorized to access this share'
      );
    });
  });

  describe('addShareKeys', () => {
    const addKeysDto: AddShareKeysDto = {
      keys: [
        {
          keyType: 'file',
          itemId: '880e8400-e29b-41d4-a716-446655440003',
          encryptedKey: 'dd'.repeat(32),
        },
      ],
    };

    it('should insert new keys when they do not exist', async () => {
      mockShareRepo.findOne.mockResolvedValue(mockShare);
      mockShareKeyRepo.findOne.mockResolvedValue(null); // no existing key
      mockShareKeyRepo.create.mockImplementation((data) => data);
      mockShareKeyRepo.save.mockResolvedValue({});

      await service.addShareKeys(shareId, sharerId, addKeysDto);

      expect(mockShareKeyRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          shareId,
          keyType: 'file',
          itemId: '880e8400-e29b-41d4-a716-446655440003',
        })
      );
    });

    it('should update existing keys (upsert)', async () => {
      const existingKey = {
        id: 'k1',
        shareId,
        keyType: 'file',
        itemId: '880e8400-e29b-41d4-a716-446655440003',
        encryptedKey: Buffer.from('aa'.repeat(32), 'hex'),
      };
      mockShareRepo.findOne.mockResolvedValue(mockShare);
      mockShareKeyRepo.findOne.mockResolvedValue(existingKey);
      mockShareKeyRepo.save.mockResolvedValue({});

      await service.addShareKeys(shareId, sharerId, addKeysDto);

      expect(mockShareKeyRepo.create).not.toHaveBeenCalled();
      expect(mockShareKeyRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedKey: Buffer.from('dd'.repeat(32), 'hex'),
        })
      );
    });

    it('should throw NotFoundException when share not found', async () => {
      mockShareRepo.findOne.mockResolvedValue(null);

      await expect(service.addShareKeys(shareId, sharerId, addKeysDto)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should throw ForbiddenException when user is not sharer', async () => {
      mockShareRepo.findOne.mockResolvedValue(mockShare);

      await expect(service.addShareKeys(shareId, recipientId, addKeysDto)).rejects.toThrow(
        ForbiddenException
      );
      await expect(service.addShareKeys(shareId, recipientId, addKeysDto)).rejects.toThrow(
        'Only the sharer can add keys'
      );
    });
  });

  describe('revokeShare', () => {
    it('should set revokedAt timestamp', async () => {
      mockShareRepo.findOne.mockResolvedValue({ ...mockShare });
      mockShareRepo.save.mockResolvedValue({});

      const before = new Date();
      await service.revokeShare(shareId, sharerId);
      const after = new Date();

      const saved = mockShareRepo.save.mock.calls[0][0];
      expect(saved.revokedAt).toBeInstanceOf(Date);
      expect(saved.revokedAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(saved.revokedAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should throw NotFoundException when share not found', async () => {
      mockShareRepo.findOne.mockResolvedValue(null);

      await expect(service.revokeShare(shareId, sharerId)).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException when user is not sharer', async () => {
      mockShareRepo.findOne.mockResolvedValue(mockShare);

      await expect(service.revokeShare(shareId, recipientId)).rejects.toThrow(ForbiddenException);
      await expect(service.revokeShare(shareId, recipientId)).rejects.toThrow(
        'Only the sharer can revoke a share'
      );
    });
  });

  describe('hideShare', () => {
    it('should set hiddenByRecipient to true', async () => {
      mockShareRepo.findOne.mockResolvedValue({ ...mockShare });
      mockShareRepo.save.mockResolvedValue({});

      await service.hideShare(shareId, recipientId);

      const saved = mockShareRepo.save.mock.calls[0][0];
      expect(saved.hiddenByRecipient).toBe(true);
    });

    it('should throw NotFoundException when share not found', async () => {
      mockShareRepo.findOne.mockResolvedValue(null);

      await expect(service.hideShare(shareId, recipientId)).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException when user is not recipient', async () => {
      mockShareRepo.findOne.mockResolvedValue(mockShare);

      await expect(service.hideShare(shareId, sharerId)).rejects.toThrow(ForbiddenException);
      await expect(service.hideShare(shareId, sharerId)).rejects.toThrow(
        'Only the recipient can hide a share'
      );
    });
  });

  describe('lookupUserByPublicKey', () => {
    it('should return true when user exists', async () => {
      mockUserRepo.findOne.mockResolvedValue({ id: recipientId });

      const result = await service.lookupUserByPublicKey(recipientPublicKey);

      expect(result).toBe(true);
      expect(mockUserRepo.findOne).toHaveBeenCalledWith({
        where: { publicKey: recipientPublicKey },
        select: ['id'],
      });
    });

    it('should return false when user does not exist', async () => {
      mockUserRepo.findOne.mockResolvedValue(null);

      const result = await service.lookupUserByPublicKey(recipientPublicKey);

      expect(result).toBe(false);
    });

    it('should strip 0x prefix from publicKey before lookup', async () => {
      mockUserRepo.findOne.mockResolvedValue({ id: recipientId });

      const result = await service.lookupUserByPublicKey('0x' + recipientPublicKey);

      expect(result).toBe(true);
      expect(mockUserRepo.findOne).toHaveBeenCalledWith({
        where: { publicKey: recipientPublicKey },
        select: ['id'],
      });
    });
  });

  describe('getPendingRotations', () => {
    it('should return revoked shares with recipient relation', async () => {
      const revokedShare = { ...mockShare, revokedAt: new Date() };
      mockShareRepo.find.mockResolvedValue([revokedShare]);

      const result = await service.getPendingRotations(sharerId);

      expect(result).toEqual([revokedShare]);
      expect(mockShareRepo.find).toHaveBeenCalledWith(
        expect.objectContaining({
          relations: ['recipient'],
          order: { revokedAt: 'ASC' },
        })
      );
    });

    it('should return empty array when no pending rotations', async () => {
      mockShareRepo.find.mockResolvedValue([]);

      const result = await service.getPendingRotations(sharerId);

      expect(result).toEqual([]);
    });
  });

  describe('completeRotation', () => {
    const revokedShare = { ...mockShare, revokedAt: new Date() };

    it('should hard-delete a revoked share', async () => {
      mockShareRepo.findOne.mockResolvedValue(revokedShare);
      mockShareRepo.remove.mockResolvedValue(revokedShare);

      await service.completeRotation(shareId, sharerId);

      expect(mockShareRepo.remove).toHaveBeenCalledWith(revokedShare);
    });

    it('should throw NotFoundException when share not found', async () => {
      mockShareRepo.findOne.mockResolvedValue(null);

      await expect(service.completeRotation(shareId, sharerId)).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException when user is not sharer', async () => {
      mockShareRepo.findOne.mockResolvedValue(revokedShare);

      await expect(service.completeRotation(shareId, recipientId)).rejects.toThrow(
        ForbiddenException
      );
      await expect(service.completeRotation(shareId, recipientId)).rejects.toThrow(
        'Only the sharer can complete rotation'
      );
    });

    it('should throw ConflictException when share is not revoked', async () => {
      mockShareRepo.findOne.mockResolvedValue(mockShare); // revokedAt is null

      await expect(service.completeRotation(shareId, sharerId)).rejects.toThrow(ConflictException);
      await expect(service.completeRotation(shareId, sharerId)).rejects.toThrow(
        'Cannot complete rotation for a non-revoked share'
      );
    });
  });

  describe('updateShareEncryptedKey', () => {
    it('should update the encrypted key', async () => {
      const newKey = 'ff'.repeat(64);
      mockShareRepo.findOne.mockResolvedValue({ ...mockShare });
      mockShareRepo.save.mockResolvedValue({});

      await service.updateShareEncryptedKey(shareId, sharerId, newKey);

      const saved = mockShareRepo.save.mock.calls[0][0];
      expect(Buffer.isBuffer(saved.encryptedKey)).toBe(true);
      expect(saved.encryptedKey.toString('hex')).toBe(newKey);
    });

    it('should throw NotFoundException when share not found', async () => {
      mockShareRepo.findOne.mockResolvedValue(null);

      await expect(
        service.updateShareEncryptedKey(shareId, sharerId, 'ff'.repeat(64))
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException when user is not sharer', async () => {
      mockShareRepo.findOne.mockResolvedValue(mockShare);

      await expect(
        service.updateShareEncryptedKey(shareId, recipientId, 'ff'.repeat(64))
      ).rejects.toThrow(ForbiddenException);
      await expect(
        service.updateShareEncryptedKey(shareId, recipientId, 'ff'.repeat(64))
      ).rejects.toThrow('Only the sharer can update share keys');
    });
  });

  // ──────────────────────────────────────────────────────
  // Invite link methods (Phase 15)
  // ──────────────────────────────────────────────────────

  describe('createInvite', () => {
    const createInviteDto = {
      itemType: 'folder' as const,
      ipnsName: testIpnsName,
      itemName: 'My Folder',
      encryptedKey: testEncryptedKey,
    };

    it('should create and save an invite entity', async () => {
      const savedInvite = {
        id: 'inv-1',
        token: 'random-token',
        sharerId,
        itemType: 'folder',
        ipnsName: testIpnsName,
        itemName: 'My Folder',
        encryptedKey: Buffer.from(testEncryptedKey, 'hex'),
        encryptedChildKeys: null,
        status: 'active',
        maxClaims: 1,
        claimCount: 0,
        expiresAt: new Date(),
        createdAt: new Date(),
      };
      mockShareInviteRepo.save.mockResolvedValue(savedInvite);

      const result = await service.createInvite(sharerId, createInviteDto);

      expect(result).toEqual(savedInvite);
      expect(mockShareInviteRepo.save).toHaveBeenCalledTimes(1);
    });

    it('should store encryptedKey as Buffer from hex', async () => {
      mockShareInviteRepo.save.mockImplementation((entity: any) => Promise.resolve(entity));

      await service.createInvite(sharerId, createInviteDto);

      // The service calls inviteRepo.create then inviteRepo.save
      // We verify via the save call that the entity has a Buffer encryptedKey
      const saveCall = mockShareInviteRepo.save.mock.calls[0][0];
      expect(Buffer.isBuffer(saveCall.encryptedKey)).toBe(true);
      expect(saveCall.encryptedKey.toString('hex')).toBe(testEncryptedKey);
    });

    it('should pass encryptedChildKeys from dto', async () => {
      const dtoWithChildren = {
        ...createInviteDto,
        encryptedChildKeys: [
          { keyType: 'file' as const, itemId: 'f1', encryptedKey: 'dd'.repeat(32) },
        ],
      };
      mockShareInviteRepo.save.mockImplementation((entity: any) => Promise.resolve(entity));

      await service.createInvite(sharerId, dtoWithChildren);

      const saveCall = mockShareInviteRepo.save.mock.calls[0][0];
      expect(saveCall.encryptedChildKeys).toEqual(dtoWithChildren.encryptedChildKeys);
    });

    it('should set encryptedChildKeys to null when not provided', async () => {
      mockShareInviteRepo.save.mockImplementation((entity: any) => Promise.resolve(entity));

      await service.createInvite(sharerId, createInviteDto);

      const saveCall = mockShareInviteRepo.save.mock.calls[0][0];
      expect(saveCall.encryptedChildKeys).toBeNull();
    });
  });

  describe('getInviteStatus', () => {
    it('should return status when invite exists and is active', async () => {
      const invite = {
        status: 'active',
        expiresAt: new Date(Date.now() + 3600_000), // 1 hour from now
      };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      const result = await service.getInviteStatus('test-token');

      expect(result).toEqual({ status: 'active' });
    });

    it('should return null when invite not found', async () => {
      mockShareInviteRepo.findOne.mockResolvedValue(null);

      const result = await service.getInviteStatus('nonexistent-token');

      expect(result).toBeNull();
    });

    it('should auto-expire and remove invite past TTL', async () => {
      const invite = {
        status: 'active',
        expiresAt: new Date(Date.now() - 1000), // expired 1 second ago
      };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);
      mockShareInviteRepo.remove.mockResolvedValue(invite);

      const result = await service.getInviteStatus('expired-token');

      expect(result).toBeNull();
      expect(mockShareInviteRepo.remove).toHaveBeenCalledWith(invite);
    });

    it('should return claimed status without auto-expiring', async () => {
      const invite = {
        status: 'claimed',
        expiresAt: new Date(Date.now() - 1000), // past expiry but already claimed
      };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      const result = await service.getInviteStatus('claimed-token');

      expect(result).toEqual({ status: 'claimed' });
      expect(mockShareInviteRepo.remove).not.toHaveBeenCalled();
    });
  });

  describe('getInviteForClaim', () => {
    it('should return active invite when valid', async () => {
      const invite = {
        id: 'inv-1',
        status: 'active',
        expiresAt: new Date(Date.now() + 3600_000),
      };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      const result = await service.getInviteForClaim('test-token');

      expect(result).toEqual(invite);
    });

    it('should return null when invite not found', async () => {
      mockShareInviteRepo.findOne.mockResolvedValue(null);

      const result = await service.getInviteForClaim('nonexistent-token');

      expect(result).toBeNull();
    });

    it('should auto-expire and return null for expired invite', async () => {
      const invite = {
        status: 'active',
        expiresAt: new Date(Date.now() - 1000),
      };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);
      mockShareInviteRepo.remove.mockResolvedValue(invite);

      const result = await service.getInviteForClaim('expired-token');

      expect(result).toBeNull();
      expect(mockShareInviteRepo.remove).toHaveBeenCalledWith(invite);
    });

    it('should return null for non-active invite (claimed)', async () => {
      const invite = {
        status: 'claimed',
        expiresAt: new Date(Date.now() + 3600_000),
      };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      const result = await service.getInviteForClaim('claimed-token');

      expect(result).toBeNull();
    });

    it('should return null for revoked invite', async () => {
      const invite = {
        status: 'revoked',
        expiresAt: new Date(Date.now() + 3600_000),
      };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      const result = await service.getInviteForClaim('revoked-token');

      expect(result).toBeNull();
    });
  });

  describe('claimInvite', () => {
    const claimDto = {
      encryptedKey: 'ff'.repeat(64),
      childKeys: [{ keyType: 'file' as const, itemId: 'f1', encryptedKey: 'ee'.repeat(32) }],
    };

    const invite = {
      id: 'inv-1',
      token: 'claim-token',
      sharerId,
      itemType: 'folder',
      ipnsName: testIpnsName,
      itemName: 'My Folder',
      encryptedKey: Buffer.from(testEncryptedKey, 'hex'),
      status: 'active',
    };

    it('should create share and share keys, return shareId', async () => {
      const newShareId = '990e8400-e29b-41d4-a716-446655440005';
      mockShareInviteRepo.findOne.mockResolvedValue(invite);
      // Atomic update succeeds
      mockShareInviteRepo.save.mockResolvedValue({});
      // No existing active share
      mockShareRepo.findOne.mockResolvedValue(null);
      // No revoked shares
      mockShareRepo.find.mockResolvedValue([]);
      // Create share
      mockShareRepo.create.mockReturnValue({ id: newShareId });
      mockShareRepo.save.mockResolvedValue({ id: newShareId });
      // Create share keys
      mockShareKeyRepo.create.mockImplementation((data) => data);
      mockShareKeyRepo.save.mockResolvedValue([]);

      // Mock the createQueryBuilder chain for the atomic UPDATE
      const mockQb = {
        update: jest.fn().mockReturnThis(),
        set: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 1 }),
      };
      (mockShareInviteRepo as any).createQueryBuilder = jest.fn().mockReturnValue(mockQb);

      const result = await service.claimInvite('claim-token', recipientId, claimDto);

      expect(result).toEqual({ shareId: newShareId });
      expect(mockShareRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          sharerId,
          recipientId,
          itemType: 'folder',
          ipnsName: testIpnsName,
        })
      );
      expect(mockShareKeyRepo.create).toHaveBeenCalledTimes(1);
      expect(mockShareKeyRepo.save).toHaveBeenCalled();
    });

    it('should throw ConflictException for self-claim', async () => {
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      await expect(service.claimInvite('claim-token', sharerId, claimDto)).rejects.toThrow(
        ConflictException
      );
      await expect(service.claimInvite('claim-token', sharerId, claimDto)).rejects.toThrow(
        'Cannot claim your own invite'
      );
    });

    it('should throw NotFoundException when invite not found', async () => {
      mockShareInviteRepo.findOne.mockResolvedValue(null);

      await expect(service.claimInvite('nonexistent', recipientId, claimDto)).rejects.toThrow(
        NotFoundException
      );
      await expect(service.claimInvite('nonexistent', recipientId, claimDto)).rejects.toThrow(
        'Invite not found or expired'
      );
    });

    it('should throw ConflictException when atomic update fails (already claimed)', async () => {
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      const mockQb = {
        update: jest.fn().mockReturnThis(),
        set: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 0 }),
      };
      (mockShareInviteRepo as any).createQueryBuilder = jest.fn().mockReturnValue(mockQb);

      await expect(service.claimInvite('claim-token', recipientId, claimDto)).rejects.toThrow(
        ConflictException
      );
      await expect(service.claimInvite('claim-token', recipientId, claimDto)).rejects.toThrow(
        'Invite already claimed, expired, or revoked'
      );
    });

    it('should return existing shareId when share already exists', async () => {
      const existingShareId = '880e8400-e29b-41d4-a716-446655440004';
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      const mockQb = {
        update: jest.fn().mockReturnThis(),
        set: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 1 }),
      };
      (mockShareInviteRepo as any).createQueryBuilder = jest.fn().mockReturnValue(mockQb);

      // Existing active share found
      mockShareRepo.findOne.mockResolvedValue({ id: existingShareId });

      const result = await service.claimInvite('claim-token', recipientId, claimDto);

      expect(result).toEqual({ shareId: existingShareId });
      // Should NOT create new share
      expect(mockShareRepo.create).not.toHaveBeenCalled();
    });
  });

  describe('getInvitesForItem', () => {
    it('should return active non-expired invites', async () => {
      const activeInvite = {
        id: 'inv-1',
        token: 'token-1',
        status: 'active',
        expiresAt: new Date(Date.now() + 3600_000),
      };
      mockShareInviteRepo.find.mockResolvedValue([activeInvite]);

      const result = await service.getInvitesForItem(sharerId, testIpnsName);

      expect(result).toEqual([activeInvite]);
      expect(mockShareInviteRepo.find).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            sharerId,
            ipnsName: testIpnsName,
            status: 'active',
          },
          order: { createdAt: 'DESC' },
        })
      );
    });

    it('should auto-clean expired invites and return only active ones', async () => {
      const activeInvite = {
        id: 'inv-1',
        status: 'active',
        expiresAt: new Date(Date.now() + 3600_000),
      };
      const expiredInvite = {
        id: 'inv-2',
        status: 'active',
        expiresAt: new Date(Date.now() - 1000),
      };
      mockShareInviteRepo.find.mockResolvedValue([activeInvite, expiredInvite]);
      mockShareInviteRepo.remove.mockResolvedValue([expiredInvite]);

      const result = await service.getInvitesForItem(sharerId, testIpnsName);

      expect(result).toEqual([activeInvite]);
      expect(mockShareInviteRepo.remove).toHaveBeenCalledWith([expiredInvite]);
    });

    it('should return empty array when no invites exist', async () => {
      mockShareInviteRepo.find.mockResolvedValue([]);

      const result = await service.getInvitesForItem(sharerId, testIpnsName);

      expect(result).toEqual([]);
    });

    it('should not call remove when no expired invites', async () => {
      const activeInvite = {
        id: 'inv-1',
        status: 'active',
        expiresAt: new Date(Date.now() + 3600_000),
      };
      mockShareInviteRepo.find.mockResolvedValue([activeInvite]);

      await service.getInvitesForItem(sharerId, testIpnsName);

      expect(mockShareInviteRepo.remove).not.toHaveBeenCalled();
    });
  });

  describe('revokeInvite', () => {
    it('should set status to revoked', async () => {
      const invite = { id: 'inv-1', sharerId, status: 'active' };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);
      mockShareInviteRepo.save.mockResolvedValue({});

      await service.revokeInvite('inv-1', sharerId);

      const saved = mockShareInviteRepo.save.mock.calls[0][0];
      expect(saved.status).toBe('revoked');
    });

    it('should throw NotFoundException when invite not found', async () => {
      mockShareInviteRepo.findOne.mockResolvedValue(null);

      await expect(service.revokeInvite('nonexistent', sharerId)).rejects.toThrow(
        NotFoundException
      );
      await expect(service.revokeInvite('nonexistent', sharerId)).rejects.toThrow(
        'Invite not found'
      );
    });

    it('should throw ForbiddenException when user is not sharer', async () => {
      const invite = { id: 'inv-1', sharerId, status: 'active' };
      mockShareInviteRepo.findOne.mockResolvedValue(invite);

      await expect(service.revokeInvite('inv-1', recipientId)).rejects.toThrow(ForbiddenException);
      await expect(service.revokeInvite('inv-1', recipientId)).rejects.toThrow(
        'Only the sharer can revoke an invite'
      );
    });
  });
});
