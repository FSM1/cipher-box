import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { SharesController } from './shares.controller';
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

  const mockReq = { user: { id: userId } } as any;

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
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<SharesController>(SharesController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createShare', () => {
    it('should return share data with hex-encoded encrypted key', async () => {
      mockSharesService.createShare.mockResolvedValue(mockShare);

      const dto = {
        recipientPublicKey,
        itemType: 'folder' as const,
        ipnsName: 'k51qzi5uqu5dg12345',
        itemName: 'My Folder',
        encryptedKey: testEncryptedKey,
      };

      const result = await controller.createShare(mockReq, dto);

      expect(result.shareId).toBe(shareId);
      expect(result.recipientId).toBe(recipientId);
      expect(result.encryptedKey).toBe(testEncryptedKey);
      expect(result.itemType).toBe('folder');
      expect(result.ipnsName).toBe('k51qzi5uqu5dg12345');
      expect(result.itemName).toBe('My Folder');
      expect(result.createdAt).toBe(mockShare.createdAt);
      expect(mockSharesService.createShare).toHaveBeenCalledWith(userId, dto);
    });
  });

  describe('getReceivedShares', () => {
    it('should return shares with sharerPublicKey', async () => {
      mockSharesService.getReceivedShares.mockResolvedValue([mockShare]);

      const result = await controller.getReceivedShares(mockReq);

      expect(result).toHaveLength(1);
      expect(result[0].shareId).toBe(shareId);
      expect(result[0].sharerPublicKey).toBe(mockShare.sharer.publicKey);
      expect(result[0].encryptedKey).toBe(testEncryptedKey);
      expect(result[0].itemType).toBe('folder');
    });

    it('should return empty array when no shares', async () => {
      mockSharesService.getReceivedShares.mockResolvedValue([]);

      const result = await controller.getReceivedShares(mockReq);

      expect(result).toEqual([]);
    });
  });

  describe('getSentShares', () => {
    it('should return shares with recipientPublicKey', async () => {
      mockSharesService.getSentShares.mockResolvedValue([mockShare]);

      const result = await controller.getSentShares(mockReq);

      expect(result).toHaveLength(1);
      expect(result[0].shareId).toBe(shareId);
      expect(result[0].recipientPublicKey).toBe(recipientPublicKey);
      expect(result[0].itemType).toBe('folder');
      expect(result[0].itemName).toBe('My Folder');
    });
  });

  describe('lookupUser', () => {
    it('should return exists true when user found', async () => {
      mockSharesService.lookupUserByPublicKey.mockResolvedValue(true);

      const result = await controller.lookupUser(recipientPublicKey);

      expect(result).toEqual({ exists: true });
    });

    it('should throw NotFoundException when user not found', async () => {
      mockSharesService.lookupUserByPublicKey.mockResolvedValue(false);

      await expect(controller.lookupUser(recipientPublicKey)).rejects.toThrow(NotFoundException);
      await expect(controller.lookupUser(recipientPublicKey)).rejects.toThrow('User not found');
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
  });

  describe('addShareKeys', () => {
    it('should call service with shareId, userId, and dto', async () => {
      mockSharesService.addShareKeys.mockResolvedValue(undefined);

      const dto = {
        keys: [
          {
            keyType: 'file' as const,
            itemId: '880e8400-e29b-41d4-a716-446655440003',
            encryptedKey: 'dd'.repeat(32),
          },
        ],
      };

      await controller.addShareKeys(mockReq, shareId, dto);

      expect(mockSharesService.addShareKeys).toHaveBeenCalledWith(shareId, userId, dto);
    });
  });

  describe('revokeShare', () => {
    it('should call service with shareId and userId', async () => {
      mockSharesService.revokeShare.mockResolvedValue(undefined);

      await controller.revokeShare(mockReq, shareId);

      expect(mockSharesService.revokeShare).toHaveBeenCalledWith(shareId, userId);
    });
  });

  describe('hideShare', () => {
    it('should call service with shareId and userId', async () => {
      mockSharesService.hideShare.mockResolvedValue(undefined);

      await controller.hideShare(mockReq, shareId);

      expect(mockSharesService.hideShare).toHaveBeenCalledWith(shareId, userId);
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
  });

  describe('completeRotation', () => {
    it('should call service with shareId and userId', async () => {
      mockSharesService.completeRotation.mockResolvedValue(undefined);

      await controller.completeRotation(mockReq, shareId);

      expect(mockSharesService.completeRotation).toHaveBeenCalledWith(shareId, userId);
    });
  });
});
