import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { SharesService } from './shares.service';
import { Share } from './entities/share.entity';
import { ShareKey } from './entities/share-key.entity';
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
    mockUserRepo = {
      findOne: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SharesService,
        { provide: getRepositoryToken(Share), useValue: mockShareRepo },
        { provide: getRepositoryToken(ShareKey), useValue: mockShareKeyRepo },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
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
});
