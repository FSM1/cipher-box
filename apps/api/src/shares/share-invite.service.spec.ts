/**
 * ShareInviteService — claim-path security invariants
 *
 * Focused on claimInvite() behavioral guarantees introduced in Phase 66.
 * Implementation files are READ-ONLY; this spec only lives in the test layer.
 */
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { ShareInviteService } from './share-invite.service';
import { ShareInvite } from './entities/share-invite.entity';
import { Share } from './entities/share.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { ClaimInviteDto } from './dto/claim-invite.dto';
import { CreateInviteDto } from './dto/create-invite.dto';

const sharerId = '550e8400-e29b-41d4-a716-446655440000';
const claimerId = '660e8400-e29b-41d4-a716-446655440001';
const rootNodeId = '770e8400-e29b-41d4-a716-446655440002';
const shareRootIpnsName = 'k51qzi5uqu5dg12345abcdef';
const rootGeneration = '3';
const token = 'test-token-abc';

const READ_HEX = 'aa'.repeat(64);
const WRITE_HEX = 'bb'.repeat(64);

const futureDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
const pastDate = new Date(Date.now() - 1000);

function makeInvite(overrides: Partial<ShareInvite> = {}): ShareInvite {
  return {
    id: 'invite-id-1',
    token,
    sharerId,
    sharer: {} as never,
    rootNodeId,
    shareRootIpnsName,
    rootGeneration,
    itemNameEncrypted: null,
    encryptedReadKey: Buffer.from('cc'.repeat(64), 'hex'),
    encryptedWriteKey: null,
    status: 'active',
    maxClaims: 1,
    claimCount: 0,
    claimedBy: null,
    expiresAt: futureDate,
    createdAt: new Date('2026-06-01T00:00:00Z'),
    ...overrides,
  } as ShareInvite;
}

describe('ShareInviteService — claimInvite security invariants', () => {
  let service: ShareInviteService;
  let mockInviteRepo: {
    findOne: jest.Mock;
    save: jest.Mock;
    remove: jest.Mock;
    create: jest.Mock;
    find: jest.Mock;
  };
  let mockIpnsRecordRepo: { findOne: jest.Mock };
  let mockDataSource: { transaction: jest.Mock };
  let mockManager: {
    createQueryBuilder: jest.Mock;
    findOne: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    find: jest.Mock;
    remove: jest.Mock;
  };
  let mockQb: {
    update: jest.Mock;
    set: jest.Mock;
    where: jest.Mock;
    andWhere: jest.Mock;
    execute: jest.Mock;
  };

  beforeEach(async () => {
    mockQb = {
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      execute: jest.fn().mockResolvedValue({ affected: 1 }),
    };

    mockManager = {
      createQueryBuilder: jest.fn().mockReturnValue(mockQb),
      findOne: jest.fn().mockResolvedValue(null), // no existing share by default
      find: jest.fn().mockResolvedValue([]),
      create: jest
        .fn()
        .mockImplementation((_Entity: unknown, data: unknown) => ({ ...(data as object) })),
      save: jest
        .fn()
        .mockImplementation((entity: unknown) =>
          Promise.resolve({ id: 'new-share-id', ...(entity as object) })
        ),
      remove: jest.fn().mockResolvedValue(undefined),
    };

    mockInviteRepo = {
      findOne: jest.fn(),
      save: jest.fn().mockImplementation((e: unknown) => Promise.resolve(e)),
      remove: jest.fn().mockResolvedValue(undefined),
      create: jest.fn().mockImplementation((d: unknown) => ({ ...(d as object) })),
      find: jest.fn().mockResolvedValue([]),
    };

    mockDataSource = {
      transaction: jest
        .fn()
        .mockImplementation((cb: (m: typeof mockManager) => unknown) => cb(mockManager)),
    };

    // Default: caller IS the registered owner of the shared node (D-01/SC#1).
    // Individual root-ownership tests override this per-case.
    mockIpnsRecordRepo = {
      findOne: jest.fn().mockResolvedValue({ id: 'ipns-record-1' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ShareInviteService,
        { provide: getRepositoryToken(ShareInvite), useValue: mockInviteRepo },
        { provide: getRepositoryToken(IpnsRecord), useValue: mockIpnsRecordRepo },
        { provide: DataSource, useValue: mockDataSource },
      ],
    }).compile();

    service = module.get<ShareInviteService>(ShareInviteService);
  });

  // ------------------------------------------------------------------ createInvite — root-ownership gate (D-01/SC#1)
  describe('createInvite — root-ownership gate (D-01/SC#1)', () => {
    function makeCreateInviteDto(overrides: Partial<CreateInviteDto> = {}): CreateInviteDto {
      return {
        shareRootIpnsName,
        rootNodeId,
        encryptedReadKey: READ_HEX,
        ...overrides,
      } as CreateInviteDto;
    }

    it('throws ForbiddenException when the caller did not register shareRootIpnsName in ipns_records', async () => {
      mockIpnsRecordRepo.findOne.mockResolvedValue(null);

      await expect(service.createInvite(sharerId, makeCreateInviteDto())).rejects.toThrow(
        ForbiddenException
      );
      expect(mockInviteRepo.save).not.toHaveBeenCalled();
    });

    it('persists the invite when the caller IS the registered owner of shareRootIpnsName', async () => {
      mockIpnsRecordRepo.findOne.mockResolvedValue({ id: 'ipns-record-1' });

      await service.createInvite(sharerId, makeCreateInviteDto());

      expect(mockIpnsRecordRepo.findOne).toHaveBeenCalledWith({
        where: { ipnsName: shareRootIpnsName, userId: sharerId },
      });
      expect(mockInviteRepo.save).toHaveBeenCalledTimes(1);
    });

    it('generates a token, sets a future expiresAt, and copies DTO fields (mechanics, D-09)', async () => {
      const dto = makeCreateInviteDto();

      const result = await service.createInvite(sharerId, dto);

      expect(typeof result.token).toBe('string');
      expect(result.token.length).toBeGreaterThan(0);
      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(result.sharerId).toBe(sharerId);
      expect(result.shareRootIpnsName).toBe(dto.shareRootIpnsName);
      expect(result.rootNodeId).toBe(dto.rootNodeId);
      expect(result.status).toBe('active');
      expect(result.maxClaims).toBe(1);
      expect(result.claimCount).toBe(0);
    });
  });

  // ------------------------------------------------------------------ T-66-E1 (priority)
  describe('T-66-E1: read-only invite cannot yield a write grant', () => {
    it('minted Share.encryptedWriteKey is null when invite.encryptedWriteKey is null, even if claimer supplies encryptedWriteKey', async () => {
      // Arrange: read-only invite (encryptedWriteKey === null)
      mockInviteRepo.findOne.mockResolvedValue(makeInvite({ encryptedWriteKey: null }));

      const dto: ClaimInviteDto = {
        encryptedReadKey: READ_HEX,
        encryptedWriteKey: WRITE_HEX, // attacker-supplied — must be ignored
      };

      // Act
      await service.claimInvite(token, claimerId, dto);

      // Assert: manager.create was called and the share data has encryptedWriteKey === null
      expect(mockManager.create).toHaveBeenCalled();
      const createCall = mockManager.create.mock.calls[0];
      const shareData = createCall[1] as Partial<Share>;
      expect(shareData.encryptedWriteKey).toBeNull();
    });
  });

  // ------------------------------------------------------------------ T-66-E1 positive
  describe('T-66-E1 positive: write invite propagates write grant from claimer ref', () => {
    it('minted Share.encryptedWriteKey is set from claimer dto when invite.encryptedWriteKey is non-null', async () => {
      // Arrange: write invite
      mockInviteRepo.findOne.mockResolvedValue(
        makeInvite({ encryptedWriteKey: Buffer.from('ff'.repeat(64), 'hex') })
      );

      const dto: ClaimInviteDto = {
        encryptedReadKey: READ_HEX,
        encryptedWriteKey: WRITE_HEX,
      };

      // Act
      await service.claimInvite(token, claimerId, dto);

      // Assert: encryptedWriteKey is the claimer's re-wrapped ref
      const createCall = mockManager.create.mock.calls[0];
      const shareData = createCall[1] as Partial<Share>;
      expect(shareData.encryptedWriteKey).toEqual(Buffer.from(WRITE_HEX, 'hex'));
    });
  });

  // ------------------------------------------------------------------ T-66-S1
  describe('T-66-S1: root identity is sourced from the invite row, not claimer input', () => {
    it('minted Share carries rootNodeId, shareRootIpnsName, rootGeneration from the invite', async () => {
      const invite = makeInvite();
      mockInviteRepo.findOne.mockResolvedValue(invite);

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      await service.claimInvite(token, claimerId, dto);

      const createCall = mockManager.create.mock.calls[0];
      const shareData = createCall[1] as Partial<Share>;

      expect(shareData.rootNodeId).toBe(rootNodeId);
      expect(shareData.shareRootIpnsName).toBe(shareRootIpnsName);
      expect(shareData.rootGeneration).toBe(rootGeneration);
    });
  });

  // ------------------------------------------------------------------ Self-claim
  describe('self-claim rejection', () => {
    it('throws ConflictException when claimerId === invite.sharerId', async () => {
      mockInviteRepo.findOne.mockResolvedValue(makeInvite());

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      await expect(service.claimInvite(token, sharerId, dto)).rejects.toThrow(ConflictException);
    });
  });

  // ------------------------------------------------------------------ Expired / non-active
  describe('expired or non-active invite', () => {
    it('throws NotFoundException for an expired active invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue(makeInvite({ expiresAt: pastDate }));

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      await expect(service.claimInvite(token, claimerId, dto)).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException for a claimed invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue(makeInvite({ status: 'claimed' }));

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      await expect(service.claimInvite(token, claimerId, dto)).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException for a revoked invite', async () => {
      mockInviteRepo.findOne.mockResolvedValue(makeInvite({ status: 'revoked' }));

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      await expect(service.claimInvite(token, claimerId, dto)).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when invite row is not found', async () => {
      mockInviteRepo.findOne.mockResolvedValue(null);

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      await expect(service.claimInvite(token, claimerId, dto)).rejects.toThrow(NotFoundException);
    });
  });

  // ------------------------------------------------------------------ Atomic claim race
  describe('atomic single-claim contention', () => {
    it('throws ConflictException when the atomic claim UPDATE affects no rows', async () => {
      // The invite passes every preflight check, but the transactional UPDATE
      // (status = active AND claim_count < max_claims AND not expired) matches 0
      // rows because a concurrent claimer already won the race. The single-claim
      // guard must reject rather than mint a second Share.
      mockInviteRepo.findOne.mockResolvedValue(makeInvite());
      mockQb.execute.mockResolvedValue({ affected: 0 });

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      await expect(service.claimInvite(token, claimerId, dto)).rejects.toThrow(ConflictException);
      expect(mockManager.create).not.toHaveBeenCalled();
    });
  });

  // ------------------------------------------------------------------ D-07 widen-only re-claim merge (SC#2)
  describe('re-claim over an existing share — widen-only merge (D-07/SC#2)', () => {
    it('same-level re-claim is a no-op', async () => {
      // Both invite and existing share are read-only at the same rootGeneration.
      mockInviteRepo.findOne.mockResolvedValue(
        makeInvite({ encryptedWriteKey: null, rootGeneration })
      );

      const existingShare = {
        id: 'existing-share-id',
        encryptedWriteKey: null,
        rootGeneration,
      } as unknown as Share;
      mockManager.findOne.mockResolvedValue(existingShare);

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      const result = await service.claimInvite(token, claimerId, dto);

      expect(result).toEqual({ shareId: 'existing-share-id' });
      expect(mockManager.create).not.toHaveBeenCalled();
      expect(mockManager.save).not.toHaveBeenCalled();
    });

    it('read→write widen upgrades the existing share and calls manager.save', async () => {
      // Invite grants write; existing share is currently read-only.
      mockInviteRepo.findOne.mockResolvedValue(
        makeInvite({ encryptedWriteKey: Buffer.from('ff'.repeat(64), 'hex'), rootGeneration })
      );

      const existingShare = {
        id: 'existing-share-id',
        encryptedWriteKey: null,
        rootGeneration,
      } as unknown as Share;
      mockManager.findOne.mockResolvedValue(existingShare);

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX, encryptedWriteKey: WRITE_HEX };

      const result = await service.claimInvite(token, claimerId, dto);

      expect(result).toEqual({ shareId: 'existing-share-id' });
      expect(mockManager.save).toHaveBeenCalledTimes(1);
      const savedShare = mockManager.save.mock.calls[0][0] as Share;
      expect(savedShare.id).toBe('existing-share-id');
      expect(savedShare.encryptedWriteKey).toEqual(Buffer.from(WRITE_HEX, 'hex'));
    });

    it('generation-bump widen advances rootGeneration and calls manager.save', async () => {
      // Invite carries a higher rootGeneration than the existing (read-only) share.
      mockInviteRepo.findOne.mockResolvedValue(
        makeInvite({ encryptedWriteKey: null, rootGeneration: '3' })
      );

      const existingShare = {
        id: 'existing-share-id',
        encryptedWriteKey: null,
        rootGeneration: '1',
        encryptedReadKey: Buffer.from('cc'.repeat(64), 'hex'),
      } as unknown as Share;
      mockManager.findOne.mockResolvedValue(existingShare);

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      const result = await service.claimInvite(token, claimerId, dto);

      expect(result).toEqual({ shareId: 'existing-share-id' });
      expect(mockManager.save).toHaveBeenCalledTimes(1);
      const savedShare = mockManager.save.mock.calls[0][0] as Share;
      expect(savedShare.rootGeneration).toBe('3');
      expect(savedShare.encryptedReadKey).toEqual(Buffer.from(READ_HEX, 'hex'));
    });

    it('BACKSTOP: a read-only re-claim over a write-capable share never downgrades encryptedWriteKey', async () => {
      // Invite is read-only (no write grant); existing share already has write access.
      mockInviteRepo.findOne.mockResolvedValue(
        makeInvite({ encryptedWriteKey: null, rootGeneration })
      );

      const existingWriteKey = Buffer.from('ee'.repeat(64), 'hex');
      const existingShare = {
        id: 'existing-share-id',
        encryptedWriteKey: existingWriteKey,
        rootGeneration,
      } as unknown as Share;
      mockManager.findOne.mockResolvedValue(existingShare);

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      const result = await service.claimInvite(token, claimerId, dto);

      expect(result).toEqual({ shareId: 'existing-share-id' });
      expect(mockManager.save).not.toHaveBeenCalled();
      // Never downgraded to null nor otherwise mutated.
      expect(existingShare.encryptedWriteKey).toEqual(existingWriteKey);
      expect(existingShare.encryptedWriteKey).not.toBeNull();
    });
  });

  // ------------------------------------------------------------------ getInvitesForItem (D-09)
  describe('getInvitesForItem', () => {
    it('returns only active, non-expired invites for the sharer + item', async () => {
      const activeInvite = makeInvite({ id: 'invite-active-1', expiresAt: futureDate });
      mockInviteRepo.find.mockResolvedValue([activeInvite]);

      const result = await service.getInvitesForItem(sharerId, shareRootIpnsName);

      expect(mockInviteRepo.find).toHaveBeenCalledWith({
        where: { sharerId, shareRootIpnsName, status: 'active' },
        order: { createdAt: 'DESC' },
      });
      expect(result).toEqual([activeInvite]);
      expect(mockInviteRepo.remove).not.toHaveBeenCalled();
    });

    it('auto-cleans expired invites and excludes them from the result', async () => {
      const activeInvite = makeInvite({ id: 'invite-active-1', expiresAt: futureDate });
      const expiredInvite = makeInvite({ id: 'invite-expired-1', expiresAt: pastDate });
      mockInviteRepo.find.mockResolvedValue([activeInvite, expiredInvite]);

      const result = await service.getInvitesForItem(sharerId, shareRootIpnsName);

      expect(result).toEqual([activeInvite]);
      expect(mockInviteRepo.remove).toHaveBeenCalledTimes(1);
      expect(mockInviteRepo.remove).toHaveBeenCalledWith([expiredInvite]);
    });
  });

  // ------------------------------------------------------------------ revokeInvite (D-09)
  describe('revokeInvite', () => {
    it('throws NotFoundException when the invite does not exist', async () => {
      mockInviteRepo.findOne.mockResolvedValue(null);

      await expect(service.revokeInvite('invite-id-1', sharerId)).rejects.toThrow(
        NotFoundException
      );
      expect(mockInviteRepo.save).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException when the caller is not the sharer', async () => {
      mockInviteRepo.findOne.mockResolvedValue(makeInvite({ sharerId }));

      await expect(service.revokeInvite('invite-id-1', claimerId)).rejects.toThrow(
        ForbiddenException
      );
      expect(mockInviteRepo.save).not.toHaveBeenCalled();
    });

    it('sets status to revoked and saves when the caller is the sharer', async () => {
      const invite = makeInvite({ sharerId, status: 'active' });
      mockInviteRepo.findOne.mockResolvedValue(invite);

      await service.revokeInvite('invite-id-1', sharerId);

      expect(mockInviteRepo.save).toHaveBeenCalledTimes(1);
      const savedInvite = mockInviteRepo.save.mock.calls[0][0] as ShareInvite;
      expect(savedInvite.status).toBe('revoked');
    });
  });
});
