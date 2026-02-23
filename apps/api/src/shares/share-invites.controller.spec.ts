import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ShareInvitesController } from './share-invites.controller';
import { SharesService } from './shares.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ShareInvite } from './entities/share-invite.entity';

describe('ShareInvitesController', () => {
  let controller: ShareInvitesController;
  let mockSharesService: {
    createInvite: jest.Mock;
    getInvitesForItem: jest.Mock;
    revokeInvite: jest.Mock;
  };

  const userId = '550e8400-e29b-41d4-a716-446655440000';
  const inviteId = '770e8400-e29b-41d4-a716-446655440002';
  const testToken = 'abc123-url-safe-token';
  const testEncryptedKey = 'cc'.repeat(64);

  const mockReq: { user: { id: string } } = { user: { id: userId } };

  const mockInvite: ShareInvite = {
    id: inviteId,
    token: testToken,
    sharerId: userId,
    sharer: {} as any,
    itemType: 'folder',
    ipnsName: 'k51qzi5uqu5dg12345',
    itemName: 'My Folder',
    encryptedKey: Buffer.from(testEncryptedKey, 'hex'),
    encryptedChildKeys: null,
    status: 'active',
    maxClaims: 1,
    claimCount: 0,
    claimedBy: null,
    expiresAt: new Date('2026-03-01T00:00:00Z'),
    createdAt: new Date('2026-02-22T00:00:00Z'),
  };

  beforeEach(async () => {
    mockSharesService = {
      createInvite: jest.fn(),
      getInvitesForItem: jest.fn(),
      revokeInvite: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ShareInvitesController],
      providers: [{ provide: SharesService, useValue: mockSharesService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<ShareInvitesController>(ShareInvitesController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createInvite', () => {
    it('should return mapped invite response from service', async () => {
      mockSharesService.createInvite.mockResolvedValue(mockInvite);

      const dto = {
        itemType: 'folder' as const,
        ipnsName: 'k51qzi5uqu5dg12345',
        itemName: 'My Folder',
        encryptedKey: testEncryptedKey,
      };

      const result = await controller.createInvite(mockReq as any, dto);

      expect(result.id).toBe(inviteId);
      expect(result.token).toBe(testToken);
      expect(result.itemType).toBe('folder');
      expect(result.ipnsName).toBe('k51qzi5uqu5dg12345');
      expect(result.itemName).toBe('My Folder');
      expect(result.status).toBe('active');
      expect(result.expiresAt).toBe(mockInvite.expiresAt);
      expect(result.createdAt).toBe(mockInvite.createdAt);
      expect(mockSharesService.createInvite).toHaveBeenCalledWith(userId, dto);
    });

    it('should not expose internal fields like encryptedKey or sharerId', async () => {
      mockSharesService.createInvite.mockResolvedValue(mockInvite);

      const dto = {
        itemType: 'folder' as const,
        ipnsName: 'k51qzi5uqu5dg12345',
        itemName: 'My Folder',
        encryptedKey: testEncryptedKey,
      };

      const result = await controller.createInvite(mockReq as any, dto);

      expect('encryptedKey' in result).toBe(false);
      expect('sharerId' in result).toBe(false);
      expect('encryptedChildKeys' in result).toBe(false);
    });
  });

  describe('listInvites', () => {
    it('should return mapped array from service', async () => {
      const invite2: ShareInvite = {
        ...mockInvite,
        id: '880e8400-e29b-41d4-a716-446655440003',
        token: 'second-token',
        itemName: 'Another Folder',
      };
      mockSharesService.getInvitesForItem.mockResolvedValue([mockInvite, invite2]);

      const result = await controller.listInvites(mockReq as any, 'k51qzi5uqu5dg12345');

      expect(result).toHaveLength(2);
      expect(result[0].id).toBe(inviteId);
      expect(result[0].token).toBe(testToken);
      expect(result[0].status).toBe('active');
      expect(result[1].id).toBe('880e8400-e29b-41d4-a716-446655440003');
      expect(result[1].token).toBe('second-token');
      expect(mockSharesService.getInvitesForItem).toHaveBeenCalledWith(
        userId,
        'k51qzi5uqu5dg12345'
      );
    });

    it('should return empty array when no invites exist', async () => {
      mockSharesService.getInvitesForItem.mockResolvedValue([]);

      const result = await controller.listInvites(mockReq as any, 'k51qzi5uqu5dg12345');

      expect(result).toEqual([]);
    });

    it('should not expose internal fields in list results', async () => {
      mockSharesService.getInvitesForItem.mockResolvedValue([mockInvite]);

      const result = await controller.listInvites(mockReq as any, 'k51qzi5uqu5dg12345');

      expect('encryptedKey' in result[0]).toBe(false);
      expect('sharerId' in result[0]).toBe(false);
    });
  });

  describe('revokeInvite', () => {
    it('should delegate to service with inviteId and userId', async () => {
      mockSharesService.revokeInvite.mockResolvedValue(undefined);

      await controller.revokeInvite(mockReq as any, inviteId);

      expect(mockSharesService.revokeInvite).toHaveBeenCalledWith(inviteId, userId);
    });

    it('should pass through service exceptions', async () => {
      mockSharesService.revokeInvite.mockRejectedValue(new NotFoundException('Invite not found'));

      await expect(controller.revokeInvite(mockReq as any, inviteId)).rejects.toThrow(
        NotFoundException
      );
    });
  });
});
