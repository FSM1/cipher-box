import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { SharesController } from './shares.controller';
import { SharesService } from './shares.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { BypassableThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { Share } from './entities/share.entity';
import { CreateShareDto } from './dto/create-share.dto';
import { RevokeForItemsDto } from './dto/revoke-for-items.dto';
import { UpdateGrantDto } from './dto/update-grant.dto';
import { PaginationQueryDto } from './dto/pagination.dto';
import { RequestWithUser } from '../common/types';

describe('SharesController', () => {
  let controller: SharesController;
  let sharesService: jest.Mocked<SharesService>;

  const mockUser = { id: 'sharer-uuid-1' };
  const mockRequest = { user: mockUser } as unknown as RequestWithUser;

  const createdAt = new Date('2026-06-01T00:00:00Z');

  // A fully-populated share (write grant + encrypted name present).
  const fullShare = {
    id: 'share-uuid-1',
    sharerId: 'sharer-uuid-1',
    recipientId: 'recipient-uuid-1',
    encryptedReadKey: Buffer.from('aabb', 'hex'),
    encryptedWriteKey: Buffer.from('ccdd', 'hex'),
    rootNodeId: 'node-uuid-1',
    shareRootIpnsName: 'k51qzi5uqu5full',
    rootGeneration: '3',
    itemNameEncrypted: Buffer.from('eeff', 'hex'),
    hiddenByRecipient: false,
    createdAt,
    sharer: { publicKey: '04sharerkey' },
    recipient: { publicKey: '04recipientkey' },
  } as unknown as Share;

  // A read-only share (write + encrypted name absent) — exercises the null ternary branches.
  const minimalShare = {
    id: 'share-uuid-2',
    sharerId: 'sharer-uuid-1',
    recipientId: 'recipient-uuid-2',
    encryptedReadKey: Buffer.from('1122', 'hex'),
    encryptedWriteKey: null,
    rootNodeId: 'node-uuid-2',
    shareRootIpnsName: 'k51qzi5uqu5min',
    rootGeneration: '0',
    itemNameEncrypted: null,
    hiddenByRecipient: false,
    createdAt,
    sharer: { publicKey: '04sharerkey2' },
    recipient: { publicKey: '04recipientkey2' },
  } as unknown as Share;

  beforeEach(async () => {
    const mockSharesService: Partial<Record<keyof SharesService, jest.Mock>> = {
      createShare: jest.fn(),
      revokeForItems: jest.fn(),
      getReceivedShares: jest.fn(),
      getSentShares: jest.fn(),
      lookupUserByPublicKey: jest.fn(),
      revokeShare: jest.fn(),
      hideShare: jest.fn(),
      updateGrant: jest.fn(),
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
    sharesService = module.get(SharesService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('createShare', () => {
    const dto: CreateShareDto = {
      recipientPublicKey: '0x04recipientkey',
      encryptedReadKey: 'aabb',
      encryptedWriteKey: 'ccdd',
      rootNodeId: 'node-uuid-1',
      shareRootIpnsName: 'k51qzi5uqu5full',
      rootGeneration: '3',
      itemNameEncrypted: 'eeff',
    };

    it('passes req.user.id and dto to the service', async () => {
      sharesService.createShare.mockResolvedValue(fullShare);

      await controller.createShare(mockRequest, dto);

      expect(sharesService.createShare).toHaveBeenCalledWith('sharer-uuid-1', dto);
    });

    it('maps a write-grant share with encrypted name to hex strings', async () => {
      sharesService.createShare.mockResolvedValue(fullShare);

      const result = await controller.createShare(mockRequest, dto);

      expect(result).toEqual({
        shareId: 'share-uuid-1',
        recipientPublicKey: '0x04recipientkey',
        encryptedReadKey: 'aabb',
        encryptedWriteKey: 'ccdd',
        rootNodeId: 'node-uuid-1',
        shareRootIpnsName: 'k51qzi5uqu5full',
        rootGeneration: '3',
        itemNameEncrypted: 'eeff',
        createdAt,
      });
    });

    it('returns null for absent encryptedWriteKey and itemNameEncrypted', async () => {
      sharesService.createShare.mockResolvedValue(minimalShare);

      const result = await controller.createShare(mockRequest, dto);

      expect(result.encryptedWriteKey).toBeNull();
      expect(result.itemNameEncrypted).toBeNull();
      expect(result.encryptedReadKey).toBe('1122');
    });

    it('propagates NotFoundException when the recipient is unknown', async () => {
      sharesService.createShare.mockRejectedValue(new NotFoundException('Recipient not found'));

      await expect(controller.createShare(mockRequest, dto)).rejects.toThrow(NotFoundException);
    });
  });

  describe('revokeForItems', () => {
    const dto: RevokeForItemsDto = { ipnsNames: ['k51qzi5uqu5full', 'k51qzi5uqu5min'] };

    it('forwards req.user.id and ipnsNames and returns the service summary', async () => {
      const summary = { revokedShares: 2, revokedInvites: 1 };
      sharesService.revokeForItems.mockResolvedValue(summary);

      const result = await controller.revokeForItems(mockRequest, dto);

      expect(sharesService.revokeForItems).toHaveBeenCalledWith('sharer-uuid-1', dto.ipnsNames);
      expect(result).toBe(summary);
    });
  });

  describe('getReceivedShares', () => {
    const pagination: PaginationQueryDto = { limit: 25, offset: 10 };

    it('passes recipient id, limit and offset to the service', async () => {
      sharesService.getReceivedShares.mockResolvedValue({ shares: [], total: 0 });

      await controller.getReceivedShares(mockRequest, pagination);

      expect(sharesService.getReceivedShares).toHaveBeenCalledWith('sharer-uuid-1', 25, 10);
    });

    it('maps received shares with sharer publicKey across both null branches', async () => {
      sharesService.getReceivedShares.mockResolvedValue({
        shares: [fullShare, minimalShare],
        total: 2,
      });

      const result = await controller.getReceivedShares(mockRequest, pagination);

      expect(result.total).toBe(2);
      expect(result.shares[0]).toEqual({
        shareId: 'share-uuid-1',
        sharerPublicKey: '04sharerkey',
        encryptedReadKey: 'aabb',
        encryptedWriteKey: 'ccdd',
        rootNodeId: 'node-uuid-1',
        shareRootIpnsName: 'k51qzi5uqu5full',
        rootGeneration: '3',
        itemNameEncrypted: 'eeff',
        createdAt,
      });
      expect(result.shares[1].encryptedWriteKey).toBeNull();
      expect(result.shares[1].itemNameEncrypted).toBeNull();
      expect(result.shares[1].sharerPublicKey).toBe('04sharerkey2');
    });
  });

  describe('getSentShares', () => {
    const pagination: PaginationQueryDto = { limit: 50, offset: 0 };

    it('passes sharer id, limit and offset to the service', async () => {
      sharesService.getSentShares.mockResolvedValue({ shares: [], total: 0 });

      await controller.getSentShares(mockRequest, pagination);

      expect(sharesService.getSentShares).toHaveBeenCalledWith('sharer-uuid-1', 50, 0);
    });

    it('maps sent shares with recipient publicKey across both null branches', async () => {
      sharesService.getSentShares.mockResolvedValue({
        shares: [fullShare, minimalShare],
        total: 2,
      });

      const result = await controller.getSentShares(mockRequest, pagination);

      expect(result.total).toBe(2);
      expect(result.shares[0]).toEqual({
        shareId: 'share-uuid-1',
        recipientPublicKey: '04recipientkey',
        encryptedReadKey: 'aabb',
        encryptedWriteKey: 'ccdd',
        rootNodeId: 'node-uuid-1',
        shareRootIpnsName: 'k51qzi5uqu5full',
        rootGeneration: '3',
        itemNameEncrypted: 'eeff',
        createdAt,
      });
      expect(result.shares[1].encryptedWriteKey).toBeNull();
      expect(result.shares[1].itemNameEncrypted).toBeNull();
      expect(result.shares[1].recipientPublicKey).toBe('04recipientkey2');
    });
  });

  describe('lookupUser', () => {
    const validKey = `0x04${'a'.repeat(128)}`;

    it('returns the service result for a well-formed public key', async () => {
      sharesService.lookupUserByPublicKey.mockResolvedValue(true);

      const result = await controller.lookupUser(validKey);

      expect(sharesService.lookupUserByPublicKey).toHaveBeenCalledWith(validKey);
      expect(result).toEqual({ exists: true });
    });

    it('returns exists:false when the key is not registered', async () => {
      sharesService.lookupUserByPublicKey.mockResolvedValue(false);

      const result = await controller.lookupUser(validKey);

      expect(result).toEqual({ exists: false });
    });

    it('rejects an empty public key without hitting the service', async () => {
      await expect(controller.lookupUser('')).rejects.toThrow(BadRequestException);
      expect(sharesService.lookupUserByPublicKey).not.toHaveBeenCalled();
    });

    it('rejects a malformed public key without hitting the service', async () => {
      await expect(controller.lookupUser('0x05deadbeef')).rejects.toThrow(BadRequestException);
      expect(sharesService.lookupUserByPublicKey).not.toHaveBeenCalled();
    });
  });

  describe('revokeShare', () => {
    it('delegates to the service with shareId and req.user.id', async () => {
      sharesService.revokeShare.mockResolvedValue(undefined);

      await controller.revokeShare(mockRequest, 'share-uuid-1');

      expect(sharesService.revokeShare).toHaveBeenCalledWith('share-uuid-1', 'sharer-uuid-1');
    });

    it('propagates ForbiddenException when the caller is not the sharer', async () => {
      sharesService.revokeShare.mockRejectedValue(
        new ForbiddenException('Only the sharer can revoke a share')
      );

      await expect(controller.revokeShare(mockRequest, 'share-uuid-1')).rejects.toThrow(
        ForbiddenException
      );
    });
  });

  describe('hideShare', () => {
    it('delegates to the service with shareId and req.user.id', async () => {
      sharesService.hideShare.mockResolvedValue(undefined);

      await controller.hideShare(mockRequest, 'share-uuid-1');

      expect(sharesService.hideShare).toHaveBeenCalledWith('share-uuid-1', 'sharer-uuid-1');
    });

    it('propagates NotFoundException when the share is missing', async () => {
      sharesService.hideShare.mockRejectedValue(new NotFoundException('Share not found'));

      await expect(controller.hideShare(mockRequest, 'missing')).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateGrant', () => {
    const dto: UpdateGrantDto = { encryptedReadKey: 'aabbcc', rootGeneration: '4' };

    it('delegates shareId, req.user.id, encryptedReadKey and rootGeneration to the service and returns 204', async () => {
      sharesService.updateGrant.mockResolvedValue(undefined);

      const result = await controller.updateGrant(mockRequest, 'share-uuid-1', dto);

      expect(sharesService.updateGrant).toHaveBeenCalledWith(
        'share-uuid-1',
        'sharer-uuid-1',
        'aabbcc',
        '4',
        undefined,
        undefined
      );
      expect(result).toBeUndefined();
    });

    it('propagates ForbiddenException when a non-sharer attempts the update', async () => {
      sharesService.updateGrant.mockRejectedValue(
        new ForbiddenException('Only the sharer can update the grant')
      );

      await expect(controller.updateGrant(mockRequest, 'share-uuid-1', dto)).rejects.toThrow(
        ForbiddenException
      );
    });

    it('propagates NotFoundException when the share is missing', async () => {
      sharesService.updateGrant.mockRejectedValue(new NotFoundException('Share not found'));

      await expect(controller.updateGrant(mockRequest, 'missing', dto)).rejects.toThrow(
        NotFoundException
      );
    });
  });
});
