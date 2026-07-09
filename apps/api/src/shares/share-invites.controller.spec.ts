import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { ShareInvitesController } from './share-invites.controller';
import { ShareInviteService } from './share-invite.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { BypassableThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { CreateInviteDto } from './dto/create-invite.dto';
import { ShareInvite } from './entities/share-invite.entity';
import { RequestWithUser } from '../common/types';

describe('ShareInvitesController', () => {
  let controller: ShareInvitesController;
  let shareInviteService: jest.Mocked<
    Pick<ShareInviteService, 'createInvite' | 'getInvitesForItem' | 'revokeInvite'>
  >;

  const mockUser = { id: 'sharer-uuid-1' };
  const mockRequest = { user: mockUser } as unknown as RequestWithUser;

  /** Build a ShareInvite entity stub with sensible defaults. */
  const makeInvite = (overrides: Partial<ShareInvite> = {}): ShareInvite =>
    ({
      id: 'invite-uuid-1',
      token: 'tok_abc123',
      sharerId: mockUser.id,
      sharer: undefined as never,
      shareRootIpnsName: 'k51qzi5uqu5testrootipnsname',
      rootNodeId: 'node-uuid-1',
      rootGeneration: '0',
      itemNameEncrypted: Buffer.from('deadbeef', 'hex'),
      encryptedReadKey: Buffer.from('cafe', 'hex'),
      encryptedWriteKey: null,
      status: 'active',
      maxClaims: 1,
      claimCount: 0,
      claimedBy: null,
      expiresAt: new Date('2026-07-07T00:00:00Z'),
      createdAt: new Date('2026-06-30T00:00:00Z'),
      ...overrides,
    }) as ShareInvite;

  beforeEach(async () => {
    const mockShareInviteService = {
      createInvite: jest.fn(),
      getInvitesForItem: jest.fn(),
      revokeInvite: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ShareInvitesController],
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

    controller = module.get<ShareInvitesController>(ShareInvitesController);
    shareInviteService = module.get(ShareInviteService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('createInvite', () => {
    const dto: CreateInviteDto = {
      shareRootIpnsName: 'k51qzi5uqu5testrootipnsname',
      rootNodeId: 'node-uuid-1',
      rootGeneration: '3',
      itemNameEncrypted: 'deadbeef',
      encryptedReadKey: 'a'.repeat(260),
    };

    it('forwards req.user.id and dto to the service', async () => {
      shareInviteService.createInvite.mockResolvedValue(makeInvite());

      await controller.createInvite(mockRequest, dto);

      expect(shareInviteService.createInvite).toHaveBeenCalledWith('sharer-uuid-1', dto);
    });

    it('maps the entity to a response with itemNameEncrypted hex-encoded', async () => {
      const invite = makeInvite({
        id: 'invite-uuid-9',
        token: 'tok_xyz',
        rootGeneration: '5',
        itemNameEncrypted: Buffer.from('deadbeef', 'hex'),
        status: 'active',
      });
      shareInviteService.createInvite.mockResolvedValue(invite);

      const result = await controller.createInvite(mockRequest, dto);

      expect(result).toEqual({
        id: 'invite-uuid-9',
        token: 'tok_xyz',
        shareRootIpnsName: invite.shareRootIpnsName,
        rootNodeId: invite.rootNodeId,
        rootGeneration: '5',
        itemNameEncrypted: 'deadbeef',
        status: 'active',
        expiresAt: invite.expiresAt,
        createdAt: invite.createdAt,
      });
    });

    it('maps a null itemNameEncrypted to null (no hex conversion)', async () => {
      shareInviteService.createInvite.mockResolvedValue(makeInvite({ itemNameEncrypted: null }));

      const result = await controller.createInvite(mockRequest, dto);

      expect(result.itemNameEncrypted).toBeNull();
    });

    it('propagates errors thrown by the service', async () => {
      shareInviteService.createInvite.mockRejectedValue(new Error('db down'));

      await expect(controller.createInvite(mockRequest, dto)).rejects.toThrow('db down');
    });
  });

  describe('listInvites', () => {
    const shareRootIpnsName = 'k51qzi5uqu5testrootipnsname';

    it('forwards req.user.id and shareRootIpnsName to the service', async () => {
      shareInviteService.getInvitesForItem.mockResolvedValue([]);

      await controller.listInvites(mockRequest, { shareRootIpnsName });

      expect(shareInviteService.getInvitesForItem).toHaveBeenCalledWith(
        'sharer-uuid-1',
        shareRootIpnsName
      );
    });

    it('returns an empty array when there are no active invites', async () => {
      shareInviteService.getInvitesForItem.mockResolvedValue([]);

      const result = await controller.listInvites(mockRequest, { shareRootIpnsName });

      expect(result).toEqual([]);
    });

    it('maps each invite, covering both hex and null itemNameEncrypted branches', async () => {
      const withName = makeInvite({
        id: 'invite-uuid-a',
        itemNameEncrypted: Buffer.from('00ff', 'hex'),
      });
      const withoutName = makeInvite({
        id: 'invite-uuid-b',
        itemNameEncrypted: null,
      });
      shareInviteService.getInvitesForItem.mockResolvedValue([withName, withoutName]);

      const result = await controller.listInvites(mockRequest, { shareRootIpnsName });

      expect(result).toHaveLength(2);
      expect(result[0]).toMatchObject({ id: 'invite-uuid-a', itemNameEncrypted: '00ff' });
      expect(result[1]).toMatchObject({ id: 'invite-uuid-b', itemNameEncrypted: null });
    });
  });

  describe('revokeInvite', () => {
    const inviteId = 'invite-uuid-1';

    it('forwards inviteId and req.user.id to the service', async () => {
      shareInviteService.revokeInvite.mockResolvedValue(undefined);

      await expect(controller.revokeInvite(mockRequest, inviteId)).resolves.toBeUndefined();
      expect(shareInviteService.revokeInvite).toHaveBeenCalledWith(inviteId, 'sharer-uuid-1');
    });

    it('propagates NotFoundException when the invite does not exist', async () => {
      shareInviteService.revokeInvite.mockRejectedValue(new NotFoundException('Invite not found'));

      await expect(controller.revokeInvite(mockRequest, inviteId)).rejects.toThrow(
        NotFoundException
      );
    });

    it('propagates ForbiddenException when a non-sharer attempts revoke', async () => {
      shareInviteService.revokeInvite.mockRejectedValue(
        new ForbiddenException('Only the sharer can revoke an invite')
      );

      await expect(controller.revokeInvite(mockRequest, inviteId)).rejects.toThrow(
        ForbiddenException
      );
    });
  });
});
