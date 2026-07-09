import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { InvitesController } from './invites.controller';
import { ShareInviteService } from './share-invite.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { BypassableThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { ClaimInviteDto } from './dto/claim-invite.dto';
import { ShareInvite } from './entities/share-invite.entity';
import { RequestWithUser } from '../common/types';

describe('InvitesController', () => {
  let controller: InvitesController;
  let shareInviteService: jest.Mocked<ShareInviteService>;

  const mockRequest = {
    user: { id: 'claimer-uuid-123' },
  } as unknown as RequestWithUser;

  /** Build a ShareInvite-shaped row for getInviteForClaim mocks. */
  const buildInvite = (overrides: Partial<ShareInvite> = {}): ShareInvite =>
    ({
      status: 'active',
      encryptedReadKey: Buffer.from('deadbeef', 'hex'),
      encryptedWriteKey: Buffer.from('cafe', 'hex'),
      rootNodeId: 'root-node-uuid',
      shareRootIpnsName: 'k51qzi5uqu5test',
      rootGeneration: '7',
      itemNameEncrypted: Buffer.from('0011', 'hex'),
      ...overrides,
    }) as ShareInvite;

  beforeEach(async () => {
    const mockShareInviteService = {
      getInviteStatus: jest.fn(),
      getInviteForClaim: jest.fn(),
      claimInvite: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [InvitesController],
      providers: [
        {
          provide: ShareInviteService,
          useValue: mockShareInviteService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(BypassableThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<InvitesController>(InvitesController);
    shareInviteService = module.get(ShareInviteService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('getInviteStatus', () => {
    it('returns active status and delegates to the service with the token', async () => {
      shareInviteService.getInviteStatus.mockResolvedValue({ status: 'active' });

      const result = await controller.getInviteStatus('tok-123');

      expect(shareInviteService.getInviteStatus).toHaveBeenCalledWith('tok-123');
      expect(result).toEqual({ status: 'active' });
    });

    it('throws NotFoundException when the service returns null (not found / expired)', async () => {
      shareInviteService.getInviteStatus.mockResolvedValue(null);

      await expect(controller.getInviteStatus('tok-missing')).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when status is not active (oracle protection)', async () => {
      shareInviteService.getInviteStatus.mockResolvedValue({ status: 'claimed' });

      await expect(controller.getInviteStatus('tok-claimed')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getInviteData', () => {
    it('throws NotFoundException when the invite is null', async () => {
      shareInviteService.getInviteForClaim.mockResolvedValue(null);

      await expect(controller.getInviteData('tok-missing')).rejects.toThrow(
        new NotFoundException('Invite not found or expired')
      );
      expect(shareInviteService.getInviteForClaim).toHaveBeenCalledWith('tok-missing');
    });

    it('maps a full invite to hex-encoded fields (write + name present)', async () => {
      shareInviteService.getInviteForClaim.mockResolvedValue(buildInvite());

      const result = await controller.getInviteData('tok-full');

      expect(result).toEqual({
        status: 'active',
        encryptedReadKey: 'deadbeef',
        encryptedWriteKey: 'cafe',
        rootNodeId: 'root-node-uuid',
        shareRootIpnsName: 'k51qzi5uqu5test',
        rootGeneration: '7',
        itemNameEncrypted: '0011',
      });
    });

    it('returns null for encryptedWriteKey and itemNameEncrypted when absent (read-only invite)', async () => {
      shareInviteService.getInviteForClaim.mockResolvedValue(
        buildInvite({ encryptedWriteKey: null, itemNameEncrypted: null })
      );

      const result = await controller.getInviteData('tok-readonly');

      expect(result.encryptedWriteKey).toBeNull();
      expect(result.itemNameEncrypted).toBeNull();
      expect(result.encryptedReadKey).toBe('deadbeef');
    });
  });

  describe('claimInvite', () => {
    const dto: ClaimInviteDto = {
      encryptedReadKey: 'aa'.repeat(40),
    };

    it('delegates to the service with token, the authenticated user id, and dto', async () => {
      shareInviteService.claimInvite.mockResolvedValue({ shareId: 'share-uuid-999' });

      const result = await controller.claimInvite(mockRequest, 'tok-claim', dto);

      expect(shareInviteService.claimInvite).toHaveBeenCalledWith(
        'tok-claim',
        'claimer-uuid-123',
        dto
      );
      expect(result).toEqual({ shareId: 'share-uuid-999' });
    });

    it('propagates service errors (e.g. already claimed / self-claim → 409)', async () => {
      // The service throws ConflictException for both the self-claim and the
      // already-claimed/expired/revoked contention paths (share-invite.service.ts),
      // and the controller propagates it unchanged.
      shareInviteService.claimInvite.mockRejectedValue(new ConflictException());

      await expect(controller.claimInvite(mockRequest, 'tok-claim', dto)).rejects.toThrow(
        ConflictException
      );
    });
  });
});
