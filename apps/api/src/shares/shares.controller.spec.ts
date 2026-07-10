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

// D-03 (SC#3 amended, documented drop): the `ipns_records(user_id) WHERE is_root`
// partial unique index is intentionally NOT added. One-root-per-user is already
// enforced at the vault layer via `vaults.owner_id` uniqueness, so an additional
// index on `ipns_records` would guard a column the entity model already treats as
// a non-authoritative creator marker. Recorded here (not just in CONTEXT.md) so
// the absence of that index isn't misread as an omission by a future reader of
// this share-plane test file.

// Contract-valid fixture constants (D-09 fixture-hardening pass) — UUID-shaped
// ids, full CIDv1 libp2p-key IPNS names (k51qzi5uqu5 + 40-60 char suffix, per
// create-share.dto.ts's @Matches validator), and full-length uncompressed
// secp256k1 public keys (04 + 128 hex chars), mirroring share-invite.service.spec.ts.
const SHARER_ID = 'a1a1a1a1-1111-4111-8111-111111111111';
const RECIPIENT_ID_1 = 'a2a2a2a2-2222-4222-8222-222222222222';
const RECIPIENT_ID_2 = 'a3a3a3a3-3333-4333-8333-333333333333';
const SHARE_ID_1 = 'b1b1b1b1-1111-4111-8111-111111111111';
const SHARE_ID_2 = 'b2b2b2b2-2222-4222-8222-222222222222';
const NODE_ID_1 = 'c1c1c1c1-1111-4111-8111-111111111111';
const NODE_ID_2 = 'c2c2c2c2-2222-4222-8222-222222222222';

const IPNS_NAME_FULL = 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz';
const IPNS_NAME_MIN = 'k51qzi5uqu5abcdefghij0123456789klmnopqrstuvwxyz9876543210zz';

const PUBLIC_KEY_SHARER = '04' + 'ab'.repeat(64);
const PUBLIC_KEY_SHARER_2 = '04' + 'cd'.repeat(64);
const PUBLIC_KEY_RECIPIENT = '04' + 'ef'.repeat(64);
const PUBLIC_KEY_RECIPIENT_2 = '04' + '12'.repeat(64);
const DTO_RECIPIENT_PUBLIC_KEY = '0x04' + 'aa'.repeat(64);

const READ_KEY_HEX = 'aa'.repeat(64);
const WRITE_KEY_HEX = 'bb'.repeat(64);
const ITEM_NAME_HEX = 'cc'.repeat(32);
const READ_KEY_HEX_MIN = 'dd'.repeat(64);
const UPDATE_READ_KEY_HEX = 'ee'.repeat(64);

describe('SharesController', () => {
  let controller: SharesController;
  let sharesService: jest.Mocked<SharesService>;

  const mockUser = { id: SHARER_ID };
  const mockRequest = { user: mockUser } as unknown as RequestWithUser;

  const createdAt = new Date('2026-06-01T00:00:00Z');

  // A fully-populated share (write grant + encrypted name present).
  const fullShare = {
    id: SHARE_ID_1,
    sharerId: SHARER_ID,
    recipientId: RECIPIENT_ID_1,
    encryptedReadKey: Buffer.from(READ_KEY_HEX, 'hex'),
    encryptedWriteKey: Buffer.from(WRITE_KEY_HEX, 'hex'),
    rootNodeId: NODE_ID_1,
    shareRootIpnsName: IPNS_NAME_FULL,
    rootGeneration: '3',
    itemNameEncrypted: Buffer.from(ITEM_NAME_HEX, 'hex'),
    hiddenByRecipient: false,
    createdAt,
    sharer: { publicKey: PUBLIC_KEY_SHARER },
    recipient: { publicKey: PUBLIC_KEY_RECIPIENT },
  } as unknown as Share;

  // A read-only share (write + encrypted name absent) — exercises the null ternary branches.
  const minimalShare = {
    id: SHARE_ID_2,
    sharerId: SHARER_ID,
    recipientId: RECIPIENT_ID_2,
    encryptedReadKey: Buffer.from(READ_KEY_HEX_MIN, 'hex'),
    encryptedWriteKey: null,
    rootNodeId: NODE_ID_2,
    shareRootIpnsName: IPNS_NAME_MIN,
    rootGeneration: '0',
    itemNameEncrypted: null,
    hiddenByRecipient: false,
    createdAt,
    sharer: { publicKey: PUBLIC_KEY_SHARER_2 },
    recipient: { publicKey: PUBLIC_KEY_RECIPIENT_2 },
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
      recipientPublicKey: DTO_RECIPIENT_PUBLIC_KEY,
      encryptedReadKey: READ_KEY_HEX,
      encryptedWriteKey: WRITE_KEY_HEX,
      rootNodeId: NODE_ID_1,
      shareRootIpnsName: IPNS_NAME_FULL,
      rootGeneration: '3',
      itemNameEncrypted: ITEM_NAME_HEX,
    };

    it('passes req.user.id and dto to the service', async () => {
      sharesService.createShare.mockResolvedValue(fullShare);

      await controller.createShare(mockRequest, dto);

      expect(sharesService.createShare).toHaveBeenCalledWith(SHARER_ID, dto);
    });

    it('maps a write-grant share with encrypted name to hex strings', async () => {
      sharesService.createShare.mockResolvedValue(fullShare);

      const result = await controller.createShare(mockRequest, dto);

      expect(result).toEqual({
        shareId: SHARE_ID_1,
        recipientPublicKey: DTO_RECIPIENT_PUBLIC_KEY,
        encryptedReadKey: READ_KEY_HEX,
        encryptedWriteKey: WRITE_KEY_HEX,
        rootNodeId: NODE_ID_1,
        shareRootIpnsName: IPNS_NAME_FULL,
        rootGeneration: '3',
        itemNameEncrypted: ITEM_NAME_HEX,
        createdAt,
      });
    });

    it('returns null for absent encryptedWriteKey and itemNameEncrypted', async () => {
      sharesService.createShare.mockResolvedValue(minimalShare);

      const result = await controller.createShare(mockRequest, dto);

      expect(result.encryptedWriteKey).toBeNull();
      expect(result.itemNameEncrypted).toBeNull();
      expect(result.encryptedReadKey).toBe(READ_KEY_HEX_MIN);
    });

    it('propagates NotFoundException when the recipient is unknown', async () => {
      sharesService.createShare.mockRejectedValue(new NotFoundException('Recipient not found'));

      await expect(controller.createShare(mockRequest, dto)).rejects.toThrow(NotFoundException);
    });
  });

  describe('revokeForItems', () => {
    const dto: RevokeForItemsDto = { ipnsNames: [IPNS_NAME_FULL, IPNS_NAME_MIN] };

    it('forwards req.user.id and ipnsNames and returns the service summary', async () => {
      const summary = { revokedShares: 2, revokedInvites: 1 };
      sharesService.revokeForItems.mockResolvedValue(summary);

      const result = await controller.revokeForItems(mockRequest, dto);

      expect(sharesService.revokeForItems).toHaveBeenCalledWith(SHARER_ID, dto.ipnsNames);
      expect(result).toBe(summary);
    });
  });

  describe('getReceivedShares', () => {
    const pagination: PaginationQueryDto = { limit: 25, offset: 10 };

    it('passes recipient id, limit and offset to the service', async () => {
      sharesService.getReceivedShares.mockResolvedValue({ shares: [], total: 0 });

      await controller.getReceivedShares(mockRequest, pagination);

      expect(sharesService.getReceivedShares).toHaveBeenCalledWith(SHARER_ID, 25, 10);
    });

    it('maps received shares with sharer publicKey across both null branches', async () => {
      sharesService.getReceivedShares.mockResolvedValue({
        shares: [fullShare, minimalShare],
        total: 2,
      });

      const result = await controller.getReceivedShares(mockRequest, pagination);

      expect(result.total).toBe(2);
      expect(result.shares[0]).toEqual({
        shareId: SHARE_ID_1,
        sharerPublicKey: PUBLIC_KEY_SHARER,
        encryptedReadKey: READ_KEY_HEX,
        encryptedWriteKey: WRITE_KEY_HEX,
        rootNodeId: NODE_ID_1,
        shareRootIpnsName: IPNS_NAME_FULL,
        rootGeneration: '3',
        itemNameEncrypted: ITEM_NAME_HEX,
        createdAt,
      });
      expect(result.shares[1].encryptedWriteKey).toBeNull();
      expect(result.shares[1].itemNameEncrypted).toBeNull();
      expect(result.shares[1].sharerPublicKey).toBe(PUBLIC_KEY_SHARER_2);
    });
  });

  describe('getSentShares', () => {
    const pagination: PaginationQueryDto = { limit: 50, offset: 0 };

    it('passes sharer id, limit and offset to the service', async () => {
      sharesService.getSentShares.mockResolvedValue({ shares: [], total: 0 });

      await controller.getSentShares(mockRequest, pagination);

      expect(sharesService.getSentShares).toHaveBeenCalledWith(SHARER_ID, 50, 0);
    });

    it('maps sent shares with recipient publicKey across both null branches', async () => {
      sharesService.getSentShares.mockResolvedValue({
        shares: [fullShare, minimalShare],
        total: 2,
      });

      const result = await controller.getSentShares(mockRequest, pagination);

      expect(result.total).toBe(2);
      expect(result.shares[0]).toEqual({
        shareId: SHARE_ID_1,
        recipientPublicKey: PUBLIC_KEY_RECIPIENT,
        encryptedReadKey: READ_KEY_HEX,
        encryptedWriteKey: WRITE_KEY_HEX,
        rootNodeId: NODE_ID_1,
        shareRootIpnsName: IPNS_NAME_FULL,
        rootGeneration: '3',
        itemNameEncrypted: ITEM_NAME_HEX,
        createdAt,
      });
      expect(result.shares[1].encryptedWriteKey).toBeNull();
      expect(result.shares[1].itemNameEncrypted).toBeNull();
      expect(result.shares[1].recipientPublicKey).toBe(PUBLIC_KEY_RECIPIENT_2);
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

      await controller.revokeShare(mockRequest, SHARE_ID_1);

      expect(sharesService.revokeShare).toHaveBeenCalledWith(SHARE_ID_1, SHARER_ID);
    });

    it('propagates ForbiddenException when the caller is not the sharer', async () => {
      sharesService.revokeShare.mockRejectedValue(
        new ForbiddenException('Only the sharer can revoke a share')
      );

      await expect(controller.revokeShare(mockRequest, SHARE_ID_1)).rejects.toThrow(
        ForbiddenException
      );
    });
  });

  describe('hideShare', () => {
    it('delegates to the service with shareId and req.user.id', async () => {
      sharesService.hideShare.mockResolvedValue(undefined);

      await controller.hideShare(mockRequest, SHARE_ID_1);

      expect(sharesService.hideShare).toHaveBeenCalledWith(SHARE_ID_1, SHARER_ID);
    });

    it('propagates NotFoundException when the share is missing', async () => {
      sharesService.hideShare.mockRejectedValue(new NotFoundException('Share not found'));

      await expect(controller.hideShare(mockRequest, 'missing')).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateGrant', () => {
    const dto: UpdateGrantDto = { encryptedReadKey: UPDATE_READ_KEY_HEX, rootGeneration: '4' };

    it('delegates shareId, req.user.id, encryptedReadKey and rootGeneration to the service and returns 204', async () => {
      sharesService.updateGrant.mockResolvedValue(undefined);

      const result = await controller.updateGrant(mockRequest, SHARE_ID_1, dto);

      expect(sharesService.updateGrant).toHaveBeenCalledWith(
        SHARE_ID_1,
        SHARER_ID,
        UPDATE_READ_KEY_HEX,
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

      await expect(controller.updateGrant(mockRequest, SHARE_ID_1, dto)).rejects.toThrow(
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
