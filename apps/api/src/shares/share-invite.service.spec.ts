/**
 * ShareInviteService — claim-path security invariants
 *
 * Focused on claimInvite() behavioral guarantees introduced in Phase 66.
 * Implementation files are READ-ONLY; this spec only lives in the test layer.
 */
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { ShareInviteService } from './share-invite.service';
import { ShareInvite } from './entities/share-invite.entity';
import { Share } from './entities/share.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { ClaimInviteDto } from './dto/claim-invite.dto';

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

  // ------------------------------------------------------------------ Idempotent re-claim
  describe('idempotent re-claim', () => {
    it('returns the existing shareId without minting a duplicate when a Share already exists', async () => {
      mockInviteRepo.findOne.mockResolvedValue(makeInvite());

      const existingShare = { id: 'existing-share-id' } as Share;
      mockManager.findOne.mockResolvedValue(existingShare);

      const dto: ClaimInviteDto = { encryptedReadKey: READ_HEX };

      const result = await service.claimInvite(token, claimerId, dto);

      expect(result).toEqual({ shareId: 'existing-share-id' });
      // manager.create should NOT have been called to mint a new share
      expect(mockManager.create).not.toHaveBeenCalled();
    });
  });
});
