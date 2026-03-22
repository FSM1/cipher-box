import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { SharesController } from './shares.controller';
import { BypassableThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { SharesService } from './shares.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Share } from './entities/share.entity';
import { ShareKey } from './entities/share-key.entity';
import { User } from '../auth/entities/user.entity';

describe('SharesController', () => {
  let controller: SharesController;
  let mockSharesService: {
    createShare: jest.Mock;
    getReceivedShares: jest.Mock;
    getSentShares: jest.Mock;
    getShareKeys: jest.Mock;
    addShareKeys: jest.Mock;
    revokeShare: jest.Mock;
    hideShare: jest.Mock;
    lookupUserByPublicKey: jest.Mock;
    getPendingRotations: jest.Mock;
    completeRotation: jest.Mock;
    updateShareEncryptedKey: jest.Mock;
  };

  const userId = '550e8400-e29b-41d4-a716-446655440000';
  const recipientId = '660e8400-e29b-41d4-a716-446655440001';
  const shareId = '770e8400-e29b-41d4-a716-446655440002';
  const recipientPublicKey = '04' + 'ab'.repeat(64);
  const testEncryptedKey = 'cc'.repeat(64);

  const mockReq: { user: { id: string } } = { user: { id: userId } };

  const mockShare: Share = {
    id: shareId,
    sharerId: userId,
    recipientId,
    itemType: 'folder',
    ipnsName: 'k51qzi5uqu5dg12345',
    itemName: 'My Folder',
    encryptedKey: Buffer.from(testEncryptedKey, 'hex'),
    hiddenByRecipient: false,
    revokedAt: null,
    shareKeys: [],
    sharer: { publicKey: '04' + 'aa'.repeat(64) } as User,
    recipient: { publicKey: recipientPublicKey } as User,
    createdAt: new Date('2026-02-20T12:00:00Z'),
    updatedAt: new Date('2026-02-20T12:00:00Z'),
  };

  beforeEach(async () => {
    mockSharesService = {
      createShare: jest.fn(),
      getReceivedShares: jest.fn(),
      getSentShares: jest.fn(),
      getShareKeys: jest.fn(),
      addShareKeys: jest.fn(),
      revokeShare: jest.fn(),
      hideShare: jest.fn(),
      lookupUserByPublicKey: jest.fn(),
      getPendingRotations: jest.fn(),
      completeRotation: jest.fn(),
      updateShareEncryptedKey: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SharesController],
      providers: [{ provide: SharesService, useValue: mockSharesService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(BypassableThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<SharesController>(SharesController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createShare', () => {
    const dto = {
      recipientPublicKey,
      itemType: 'folder' as const,
      ipnsName: 'k51qzi5uqu5dg12345',
      itemName: 'My Folder',
      encryptedKey: testEncryptedKey,
    };

    it('should return share data with hex-encoded encrypted key', async () => {
      mockSharesService.createShare.mockResolvedValue(mockShare);

      const result = await controller.createShare(mockReq, dto);

      expect(result.shareId).toBe(shareId);
      expect(result.encryptedKey).toBe(testEncryptedKey);
      expect('recipientId' in result).toBe(false);
      expect(result.itemType).toBe('folder');
      expect(result.ipnsName).toBe('k51qzi5uqu5dg12345');
      expect(result.itemName).toBe('My Folder');
      expect(result.createdAt).toBe(mockShare.createdAt);
      expect(mockSharesService.createShare).toHaveBeenCalledWith(userId, dto);
    });

    it('should not expose internal fields sharerId or recipientId', async () => {
      mockSharesService.createShare.mockResolvedValue(mockShare);

      const result = await controller.createShare(mockReq, dto);

      expect('sharerId' in result).toBe(false);
      expect('recipientId' in result).toBe(false);
      expect('hiddenByRecipient' in result).toBe(false);
    });

    it('should propagate NotFoundException when recipient not found', async () => {
      mockSharesService.createShare.mockRejectedValue(new NotFoundException('Recipient not found'));

      await expect(controller.createShare(mockReq, dto)).rejects.toThrow(NotFoundException);
    });

    it('should propagate ConflictException for duplicate share', async () => {
      mockSharesService.createShare.mockRejectedValue(
        new ConflictException('Share already exists for this item and recipient')
      );

      await expect(controller.createShare(mockReq, dto)).rejects.toThrow(ConflictException);
    });

    it('should propagate ConflictException for self-share', async () => {
      mockSharesService.createShare.mockRejectedValue(
        new ConflictException('Cannot share with yourself')
      );

      await expect(controller.createShare(mockReq, dto)).rejects.toThrow(ConflictException);
    });
  });

  describe('getReceivedShares', () => {
    const pagination = { limit: 50, offset: 0 };

    it('should return paginated shares with sharerPublicKey', async () => {
      mockSharesService.getReceivedShares.mockResolvedValue({ shares: [mockShare], total: 1 });

      const result = await controller.getReceivedShares(mockReq, pagination);

      expect(result.shares).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.shares[0].shareId).toBe(shareId);
      expect(result.shares[0].sharerPublicKey).toBe(mockShare.sharer.publicKey);
      expect(result.shares[0].encryptedKey).toBe(testEncryptedKey);
      expect(result.shares[0].itemType).toBe('folder');
    });

    it('should return empty array when no shares', async () => {
      mockSharesService.getReceivedShares.mockResolvedValue({ shares: [], total: 0 });

      const result = await controller.getReceivedShares(mockReq, pagination);

      expect(result.shares).toEqual([]);
      expect(result.total).toBe(0);
    });

    it('should pass pagination params to service', async () => {
      mockSharesService.getReceivedShares.mockResolvedValue({ shares: [], total: 0 });

      await controller.getReceivedShares(mockReq, { limit: 10, offset: 20 });

      expect(mockSharesService.getReceivedShares).toHaveBeenCalledWith(userId, 10, 20);
    });

    it('should not expose internal fields in received shares', async () => {
      mockSharesService.getReceivedShares.mockResolvedValue({ shares: [mockShare], total: 1 });

      const result = await controller.getReceivedShares(mockReq, pagination);

      expect('sharerId' in result.shares[0]).toBe(false);
      expect('recipientId' in result.shares[0]).toBe(false);
      expect('hiddenByRecipient' in result.shares[0]).toBe(false);
      expect('revokedAt' in result.shares[0]).toBe(false);
    });

    it('should map multiple shares correctly', async () => {
      const secondShare: Share = {
        ...mockShare,
        id: '990e8400-e29b-41d4-a716-446655440099',
        itemType: 'file',
        itemName: 'Secret.txt',
        ipnsName: 'k51qzi5uqu5dg99999',
        encryptedKey: Buffer.from('ee'.repeat(64), 'hex'),
        sharer: { publicKey: '04' + 'ff'.repeat(64) } as User,
      };
      mockSharesService.getReceivedShares.mockResolvedValue({
        shares: [mockShare, secondShare],
        total: 2,
      });

      const result = await controller.getReceivedShares(mockReq, pagination);

      expect(result.shares).toHaveLength(2);
      expect(result.total).toBe(2);
      expect(result.shares[0].itemName).toBe('My Folder');
      expect(result.shares[1].itemName).toBe('Secret.txt');
      expect(result.shares[1].itemType).toBe('file');
      expect(result.shares[1].encryptedKey).toBe('ee'.repeat(64));
    });
  });

  describe('getSentShares', () => {
    const pagination = { limit: 50, offset: 0 };

    it('should return paginated shares with recipientPublicKey', async () => {
      mockSharesService.getSentShares.mockResolvedValue({ shares: [mockShare], total: 1 });

      const result = await controller.getSentShares(mockReq, pagination);

      expect(result.shares).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.shares[0].shareId).toBe(shareId);
      expect(result.shares[0].recipientPublicKey).toBe(recipientPublicKey);
      expect(result.shares[0].itemType).toBe('folder');
      expect(result.shares[0].itemName).toBe('My Folder');
    });

    it('should pass pagination params to service', async () => {
      mockSharesService.getSentShares.mockResolvedValue({ shares: [], total: 0 });
      await controller.getSentShares(mockReq, { limit: 10, offset: 20 });
      expect(mockSharesService.getSentShares).toHaveBeenCalledWith(userId, 10, 20);
    });

    it('should not expose encryptedKey in sent shares response', async () => {
      mockSharesService.getSentShares.mockResolvedValue({ shares: [mockShare], total: 1 });

      const result = await controller.getSentShares(mockReq, pagination);

      expect('encryptedKey' in result.shares[0]).toBe(false);
      expect('sharerId' in result.shares[0]).toBe(false);
      expect('recipientId' in result.shares[0]).toBe(false);
    });

    it('should return empty result set', async () => {
      mockSharesService.getSentShares.mockResolvedValue({ shares: [], total: 0 });

      const result = await controller.getSentShares(mockReq, pagination);

      expect(result.shares).toEqual([]);
      expect(result.total).toBe(0);
    });
  });

  describe('lookupUser', () => {
    it('should return exists true when user found', async () => {
      mockSharesService.lookupUserByPublicKey.mockResolvedValue(true);

      const validKey = '0x04' + 'ab'.repeat(64);
      const result = await controller.lookupUser(validKey);

      expect(result).toEqual({ exists: true });
    });

    it('should return exists false when user not found', async () => {
      mockSharesService.lookupUserByPublicKey.mockResolvedValue(false);

      const validKey = '0x04' + 'ab'.repeat(64);
      const result = await controller.lookupUser(validKey);

      expect(result).toEqual({ exists: false });
    });

    it('should throw BadRequestException for invalid public key format', async () => {
      await expect(controller.lookupUser('not-a-key')).rejects.toThrow(BadRequestException);
      await expect(controller.lookupUser('0x04short')).rejects.toThrow(BadRequestException);
      await expect(controller.lookupUser('')).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for null or undefined publicKey', async () => {
      await expect(controller.lookupUser(null as unknown as string)).rejects.toThrow(
        BadRequestException
      );
      await expect(controller.lookupUser(undefined as unknown as string)).rejects.toThrow(
        BadRequestException
      );
    });

    it('should throw BadRequestException for key without 0x04 prefix', async () => {
      const keyWithout04 = '0x05' + 'ab'.repeat(64);
      await expect(controller.lookupUser(keyWithout04)).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for key that is too long', async () => {
      const tooLong = '0x04' + 'ab'.repeat(65);
      await expect(controller.lookupUser(tooLong)).rejects.toThrow(BadRequestException);
    });

    it('should accept case-insensitive hex characters', async () => {
      mockSharesService.lookupUserByPublicKey.mockResolvedValue(true);

      const mixedCaseKey = '0x04' + 'aAbBcCdD'.repeat(16);
      const result = await controller.lookupUser(mixedCaseKey);

      expect(result).toEqual({ exists: true });
    });
  });

  describe('getPendingRotations', () => {
    it('should return revoked shares with recipientPublicKey and revokedAt', async () => {
      const revokedAt = new Date('2026-02-21T10:00:00Z');
      const revokedShare = { ...mockShare, revokedAt };
      mockSharesService.getPendingRotations.mockResolvedValue([revokedShare]);

      const result = await controller.getPendingRotations(mockReq);

      expect(result).toHaveLength(1);
      expect(result[0].shareId).toBe(shareId);
      expect(result[0].recipientPublicKey).toBe(recipientPublicKey);
      expect(result[0].revokedAt).toBe(revokedAt);
    });

    it('should return empty array when no pending rotations', async () => {
      mockSharesService.getPendingRotations.mockResolvedValue([]);

      const result = await controller.getPendingRotations(mockReq);

      expect(result).toEqual([]);
    });

    it('should map multiple pending rotations correctly', async () => {
      const revokedAt1 = new Date('2026-02-21T10:00:00Z');
      const revokedAt2 = new Date('2026-02-22T15:00:00Z');
      const share1 = { ...mockShare, revokedAt: revokedAt1 };
      const share2 = {
        ...mockShare,
        id: '880e8400-e29b-41d4-a716-446655440088',
        ipnsName: 'k51qzi5uqu5dg99999',
        itemName: 'Other Folder',
        revokedAt: revokedAt2,
      };
      mockSharesService.getPendingRotations.mockResolvedValue([share1, share2]);

      const result = await controller.getPendingRotations(mockReq);

      expect(result).toHaveLength(2);
      expect(result[0].revokedAt).toBe(revokedAt1);
      expect(result[1].revokedAt).toBe(revokedAt2);
      expect(result[1].itemName).toBe('Other Folder');
    });

    it('should not expose internal fields in pending rotation response', async () => {
      const revokedShare = { ...mockShare, revokedAt: new Date() };
      mockSharesService.getPendingRotations.mockResolvedValue([revokedShare]);

      const result = await controller.getPendingRotations(mockReq);

      expect('sharerId' in result[0]).toBe(false);
      expect('encryptedKey' in result[0]).toBe(false);
      expect('hiddenByRecipient' in result[0]).toBe(false);
    });
  });

  describe('getShareKeys', () => {
    it('should return keys with hex-encoded encryptedKey', async () => {
      const keyHex = 'dd'.repeat(32);
      const mockKeys: ShareKey[] = [
        {
          id: 'k1',
          shareId,
          keyType: 'file',
          itemId: '880e8400-e29b-41d4-a716-446655440003',
          encryptedKey: Buffer.from(keyHex, 'hex'),
          share: {} as Share,
          createdAt: new Date(),
        },
      ];
      mockSharesService.getShareKeys.mockResolvedValue(mockKeys);

      const result = await controller.getShareKeys(mockReq, shareId);

      expect(result).toHaveLength(1);
      expect(result[0].keyType).toBe('file');
      expect(result[0].itemId).toBe('880e8400-e29b-41d4-a716-446655440003');
      expect(result[0].encryptedKey).toBe(keyHex);
      expect(mockSharesService.getShareKeys).toHaveBeenCalledWith(shareId, userId);
    });

    it('should return empty array when share has no child keys', async () => {
      mockSharesService.getShareKeys.mockResolvedValue([]);

      const result = await controller.getShareKeys(mockReq, shareId);

      expect(result).toEqual([]);
    });

    it('should map multiple keys with different types', async () => {
      const mockKeys: ShareKey[] = [
        {
          id: 'k1',
          shareId,
          keyType: 'file',
          itemId: '880e8400-e29b-41d4-a716-446655440003',
          encryptedKey: Buffer.from('aa'.repeat(32), 'hex'),
          share: {} as Share,
          createdAt: new Date(),
        },
        {
          id: 'k2',
          shareId,
          keyType: 'folder',
          itemId: '990e8400-e29b-41d4-a716-446655440004',
          encryptedKey: Buffer.from('bb'.repeat(32), 'hex'),
          share: {} as Share,
          createdAt: new Date(),
        },
      ];
      mockSharesService.getShareKeys.mockResolvedValue(mockKeys);

      const result = await controller.getShareKeys(mockReq, shareId);

      expect(result).toHaveLength(2);
      expect(result[0].keyType).toBe('file');
      expect(result[0].encryptedKey).toBe('aa'.repeat(32));
      expect(result[1].keyType).toBe('folder');
      expect(result[1].encryptedKey).toBe('bb'.repeat(32));
    });

    it('should propagate NotFoundException when share not found', async () => {
      mockSharesService.getShareKeys.mockRejectedValue(new NotFoundException('Share not found'));

      await expect(controller.getShareKeys(mockReq, shareId)).rejects.toThrow(NotFoundException);
    });

    it('should propagate ForbiddenException when user is not sharer or recipient', async () => {
      mockSharesService.getShareKeys.mockRejectedValue(
        new ForbiddenException('Not authorized to access this share')
      );

      await expect(controller.getShareKeys(mockReq, shareId)).rejects.toThrow(ForbiddenException);
    });
  });

  describe('addShareKeys', () => {
    const dto = {
      keys: [
        {
          keyType: 'file' as const,
          itemId: '880e8400-e29b-41d4-a716-446655440003',
          encryptedKey: 'dd'.repeat(32),
        },
      ],
    };

    it('should call service with shareId, userId, and dto', async () => {
      mockSharesService.addShareKeys.mockResolvedValue(undefined);

      await controller.addShareKeys(mockReq, shareId, dto);

      expect(mockSharesService.addShareKeys).toHaveBeenCalledWith(shareId, userId, dto);
    });

    it('should propagate NotFoundException when share not found', async () => {
      mockSharesService.addShareKeys.mockRejectedValue(new NotFoundException('Share not found'));

      await expect(controller.addShareKeys(mockReq, shareId, dto)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should propagate ForbiddenException when user is not the sharer', async () => {
      mockSharesService.addShareKeys.mockRejectedValue(
        new ForbiddenException('Only the sharer can add keys')
      );

      await expect(controller.addShareKeys(mockReq, shareId, dto)).rejects.toThrow(
        ForbiddenException
      );
    });
  });

  describe('revokeShare', () => {
    it('should call service with shareId and userId', async () => {
      mockSharesService.revokeShare.mockResolvedValue(undefined);

      await controller.revokeShare(mockReq, shareId);

      expect(mockSharesService.revokeShare).toHaveBeenCalledWith(shareId, userId);
    });

    it('should propagate NotFoundException when share not found', async () => {
      mockSharesService.revokeShare.mockRejectedValue(new NotFoundException('Share not found'));

      await expect(controller.revokeShare(mockReq, shareId)).rejects.toThrow(NotFoundException);
    });

    it('should propagate ForbiddenException when user is not the sharer', async () => {
      mockSharesService.revokeShare.mockRejectedValue(
        new ForbiddenException('Only the sharer can revoke a share')
      );

      await expect(controller.revokeShare(mockReq, shareId)).rejects.toThrow(ForbiddenException);
    });
  });

  describe('hideShare', () => {
    it('should call service with shareId and userId', async () => {
      mockSharesService.hideShare.mockResolvedValue(undefined);

      await controller.hideShare(mockReq, shareId);

      expect(mockSharesService.hideShare).toHaveBeenCalledWith(shareId, userId);
    });

    it('should propagate NotFoundException when share not found', async () => {
      mockSharesService.hideShare.mockRejectedValue(new NotFoundException('Share not found'));

      await expect(controller.hideShare(mockReq, shareId)).rejects.toThrow(NotFoundException);
    });

    it('should propagate ForbiddenException when user is not the recipient', async () => {
      mockSharesService.hideShare.mockRejectedValue(
        new ForbiddenException('Only the recipient can hide a share')
      );

      await expect(controller.hideShare(mockReq, shareId)).rejects.toThrow(ForbiddenException);
    });
  });

  describe('updateShareEncryptedKey', () => {
    it('should call service with shareId, userId, and encryptedKey', async () => {
      mockSharesService.updateShareEncryptedKey.mockResolvedValue(undefined);
      const newKey = 'ff'.repeat(64);

      await controller.updateShareEncryptedKey(mockReq, shareId, { encryptedKey: newKey });

      expect(mockSharesService.updateShareEncryptedKey).toHaveBeenCalledWith(
        shareId,
        userId,
        newKey
      );
    });

    it('should propagate NotFoundException when share not found', async () => {
      mockSharesService.updateShareEncryptedKey.mockRejectedValue(
        new NotFoundException('Share not found')
      );

      await expect(
        controller.updateShareEncryptedKey(mockReq, shareId, { encryptedKey: 'ff'.repeat(64) })
      ).rejects.toThrow(NotFoundException);
    });

    it('should propagate ForbiddenException when user is not the sharer', async () => {
      mockSharesService.updateShareEncryptedKey.mockRejectedValue(
        new ForbiddenException('Only the sharer can update share keys')
      );

      await expect(
        controller.updateShareEncryptedKey(mockReq, shareId, { encryptedKey: 'ff'.repeat(64) })
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('completeRotation', () => {
    it('should call service with shareId and userId', async () => {
      mockSharesService.completeRotation.mockResolvedValue(undefined);

      await controller.completeRotation(mockReq, shareId);

      expect(mockSharesService.completeRotation).toHaveBeenCalledWith(shareId, userId);
    });

    it('should propagate NotFoundException when share not found', async () => {
      mockSharesService.completeRotation.mockRejectedValue(
        new NotFoundException('Share not found')
      );

      await expect(controller.completeRotation(mockReq, shareId)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should propagate ForbiddenException when user is not the sharer', async () => {
      mockSharesService.completeRotation.mockRejectedValue(
        new ForbiddenException('Only the sharer can complete rotation')
      );

      await expect(controller.completeRotation(mockReq, shareId)).rejects.toThrow(
        ForbiddenException
      );
    });

    it('should propagate ConflictException when share is not revoked', async () => {
      mockSharesService.completeRotation.mockRejectedValue(
        new ConflictException('Cannot complete rotation for a non-revoked share')
      );

      await expect(controller.completeRotation(mockReq, shareId)).rejects.toThrow(
        ConflictException
      );
    });
  });
});
