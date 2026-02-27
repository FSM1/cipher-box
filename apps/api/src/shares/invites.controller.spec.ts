import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { InvitesController } from './invites.controller';
import { SharesService } from './shares.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ShareInvite } from './entities/share-invite.entity';
import { User } from '../auth/entities/user.entity';
import { RequestWithUser } from '../common/types';
import { ParseTokenPipe } from '../common/pipes/parse-token.pipe';

describe('InvitesController', () => {
  let controller: InvitesController;
  let mockSharesService: {
    getInviteStatus: jest.Mock;
    getInviteForClaim: jest.Mock;
    claimInvite: jest.Mock;
  };

  const userId = '550e8400-e29b-41d4-a716-446655440000';
  const testToken = 'abc123-url-safe-token';
  const testEncryptedKey = 'cc'.repeat(64);

  const mockReq: { user: { id: string } } = { user: { id: userId } };

  const mockInvite: ShareInvite = {
    id: '770e8400-e29b-41d4-a716-446655440002',
    token: testToken,
    sharerId: '660e8400-e29b-41d4-a716-446655440001',
    sharer: {} as User,
    itemType: 'folder',
    ipnsName: 'k51qzi5uqu5dg12345',
    itemName: 'My Folder',
    encryptedKey: Buffer.from(testEncryptedKey, 'hex'),
    encryptedChildKeys: [{ keyType: 'file', itemId: 'f1', encryptedKey: 'dd'.repeat(32) }],
    status: 'active',
    maxClaims: 1,
    claimCount: 0,
    claimedBy: null,
    expiresAt: new Date('2026-03-01T00:00:00Z'),
    createdAt: new Date('2026-02-22T00:00:00Z'),
  };

  beforeEach(async () => {
    mockSharesService = {
      getInviteStatus: jest.fn(),
      getInviteForClaim: jest.fn(),
      claimInvite: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [InvitesController],
      providers: [{ provide: SharesService, useValue: mockSharesService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<InvitesController>(InvitesController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getInviteStatus', () => {
    it('should return status from service when invite exists', async () => {
      mockSharesService.getInviteStatus.mockResolvedValue({ status: 'active' });

      const result = await controller.getInviteStatus(testToken);

      expect(result).toEqual({ status: 'active' });
      expect(mockSharesService.getInviteStatus).toHaveBeenCalledWith(testToken);
    });

    it('should throw NotFoundException when service returns null (expired/not found)', async () => {
      mockSharesService.getInviteStatus.mockResolvedValue(null);

      await expect(controller.getInviteStatus(testToken)).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException for non-active status (prevents token-existence oracle)', async () => {
      mockSharesService.getInviteStatus.mockResolvedValue({ status: 'claimed' });

      await expect(controller.getInviteStatus(testToken)).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException for revoked status', async () => {
      mockSharesService.getInviteStatus.mockResolvedValue({ status: 'revoked' });

      await expect(controller.getInviteStatus(testToken)).rejects.toThrow(NotFoundException);
    });
  });

  describe('ParseTokenPipe (applied to all endpoints)', () => {
    const pipe = new ParseTokenPipe();

    it('should accept valid base64url tokens', () => {
      expect(pipe.transform('abcdefghijklmnopqrstuv')).toBe('abcdefghijklmnopqrstuv');
    });

    it('should reject tokens with invalid characters', () => {
      expect(() => pipe.transform("'; DROP TABLE--")).toThrow(BadRequestException);
    });

    it('should reject overly long tokens', () => {
      expect(() => pipe.transform('a'.repeat(100))).toThrow(BadRequestException);
    });

    it('should reject empty tokens', () => {
      expect(() => pipe.transform('')).toThrow(BadRequestException);
    });
  });

  describe('getInviteData', () => {
    it('should return full invite data with hex-encoded encrypted key', async () => {
      mockSharesService.getInviteForClaim.mockResolvedValue(mockInvite);

      const result = await controller.getInviteData(testToken);

      expect(result.status).toBe('active');
      expect(result.encryptedKey).toBe(testEncryptedKey);
      expect(result.encryptedChildKeys).toEqual(mockInvite.encryptedChildKeys);
      expect(result.itemType).toBe('folder');
      expect(result.ipnsName).toBe('k51qzi5uqu5dg12345');
      expect(result.itemName).toBe('My Folder');
      expect(mockSharesService.getInviteForClaim).toHaveBeenCalledWith(testToken);
    });

    it('should throw NotFoundException when service returns null', async () => {
      mockSharesService.getInviteForClaim.mockResolvedValue(null);

      await expect(controller.getInviteData(testToken)).rejects.toThrow(NotFoundException);
      await expect(controller.getInviteData(testToken)).rejects.toThrow(
        'Invite not found or expired'
      );
    });

    it('should return null encryptedChildKeys when invite has none', async () => {
      const inviteNoChildren = { ...mockInvite, encryptedChildKeys: null };
      mockSharesService.getInviteForClaim.mockResolvedValue(inviteNoChildren);

      const result = await controller.getInviteData(testToken);

      expect(result.encryptedChildKeys).toBeNull();
    });
  });

  describe('claimInvite', () => {
    it('should delegate to service and return shareId', async () => {
      const shareId = '880e8400-e29b-41d4-a716-446655440003';
      mockSharesService.claimInvite.mockResolvedValue({ shareId });

      const dto = {
        encryptedKey: 'ff'.repeat(64),
        childKeys: [{ keyType: 'file' as const, itemId: 'f1', encryptedKey: 'ee'.repeat(32) }],
      };

      const result = await controller.claimInvite(mockReq as RequestWithUser, testToken, dto);

      expect(result).toEqual({ shareId });
      expect(mockSharesService.claimInvite).toHaveBeenCalledWith(testToken, userId, dto);
    });

    it('should pass through service exceptions', async () => {
      mockSharesService.claimInvite.mockRejectedValue(
        new NotFoundException('Invite not found or expired')
      );

      const dto = { encryptedKey: 'ff'.repeat(64) };

      await expect(
        controller.claimInvite(mockReq as RequestWithUser, testToken, dto)
      ).rejects.toThrow(NotFoundException);
    });
  });
});
