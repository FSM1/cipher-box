import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { DeviceApprovalService } from './device-approval.service';
import { DeviceApproval } from './device-approval.entity';
import { CreateApprovalDto } from './dto/create-approval.dto';
import { RespondApprovalDto } from './dto/respond-approval.dto';

describe('DeviceApprovalService', () => {
  let service: DeviceApprovalService;
  let mockRepo: {
    findOne: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
    find: jest.Mock;
    remove: jest.Mock;
    manager: {
      transaction: jest.Mock;
      findOne: jest.Mock;
      save: jest.Mock;
    };
  };

  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testRequestId = '660e8400-e29b-41d4-a716-446655440001';
  const testDeviceId = 'a'.repeat(64);
  const testRespondingDeviceId = 'b'.repeat(64);
  const testDeviceName = 'Chrome on macOS';
  const testEphemeralPublicKey = '04' + 'c'.repeat(128);
  const testEncryptedFactorKey = 'd'.repeat(256);

  const createDto: CreateApprovalDto = {
    deviceId: testDeviceId,
    deviceName: testDeviceName,
    ephemeralPublicKey: testEphemeralPublicKey,
  };

  const makePendingApproval = (overrides?: Partial<DeviceApproval>): DeviceApproval => ({
    id: testRequestId,
    userId: testUserId,
    deviceId: testDeviceId,
    deviceName: testDeviceName,
    ephemeralPublicKey: testEphemeralPublicKey,
    status: 'pending',
    encryptedFactorKey: null,
    createdAt: new Date('2026-02-15T10:00:00.000Z'),
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    respondedBy: null,
    ...overrides,
  });

  beforeEach(async () => {
    const mockManager = {
      findOne: jest.fn(),
      save: jest.fn(),
    };
    mockRepo = {
      findOne: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
      remove: jest.fn(),
      manager: {
        ...mockManager,
        transaction: jest
          .fn()
          .mockImplementation(async (cb: (manager: typeof mockManager) => Promise<void>) => {
            await cb(mockManager);
          }),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeviceApprovalService,
        {
          provide: getRepositoryToken(DeviceApproval),
          useValue: mockRepo,
        },
      ],
    }).compile();

    service = module.get<DeviceApprovalService>(DeviceApprovalService);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  describe('createRequest', () => {
    it('should create approval with correct fields and return requestId', async () => {
      const savedApproval = makePendingApproval();
      mockRepo.create.mockReturnValue(savedApproval);
      mockRepo.save.mockResolvedValue(savedApproval);

      const result = await service.createRequest(testUserId, createDto);

      expect(mockRepo.create).toHaveBeenCalledWith({
        userId: testUserId,
        deviceId: testDeviceId,
        deviceName: testDeviceName,
        ephemeralPublicKey: testEphemeralPublicKey,
        status: 'pending',
        expiresAt: expect.any(Date),
      });
      expect(mockRepo.save).toHaveBeenCalledWith(savedApproval);
      expect(result).toEqual({ requestId: testRequestId });
    });

    it('should set expiresAt to 5 minutes from now', async () => {
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2026-02-15T12:00:00.000Z'));

      const savedApproval = makePendingApproval();
      mockRepo.create.mockReturnValue(savedApproval);
      mockRepo.save.mockResolvedValue(savedApproval);

      await service.createRequest(testUserId, createDto);

      const createCall = mockRepo.create.mock.calls[0][0];
      const expectedExpiry = new Date('2026-02-15T12:05:00.000Z');
      expect(createCall.expiresAt.getTime()).toBe(expectedExpiry.getTime());
    });
  });

  describe('getStatus', () => {
    it('should return status for a valid pending request', async () => {
      const approval = makePendingApproval();
      mockRepo.findOne.mockResolvedValue(approval);

      const result = await service.getStatus(testRequestId, testUserId);

      expect(mockRepo.findOne).toHaveBeenCalledWith({
        where: { id: testRequestId, userId: testUserId },
      });
      expect(result).toEqual({ status: 'pending' });
    });

    it('should throw NotFoundException when request not found', async () => {
      mockRepo.findOne.mockResolvedValue(null);

      await expect(service.getStatus(testRequestId, testUserId)).rejects.toThrow(NotFoundException);
      await expect(service.getStatus(testRequestId, testUserId)).rejects.toThrow(
        'Approval request not found'
      );
    });

    it('should auto-expire pending request past TTL', async () => {
      const expiredApproval = makePendingApproval({
        expiresAt: new Date(Date.now() - 1000),
      });
      mockRepo.findOne.mockResolvedValue(expiredApproval);
      mockRepo.save.mockResolvedValue({ ...expiredApproval, status: 'expired' });

      const result = await service.getStatus(testRequestId, testUserId);

      expect(expiredApproval.status).toBe('expired');
      expect(mockRepo.save).toHaveBeenCalledWith(expiredApproval);
      expect(result).toEqual({ status: 'expired' });
    });

    it('should not auto-expire non-pending request even if past TTL', async () => {
      const approvedApproval = makePendingApproval({
        status: 'approved',
        expiresAt: new Date(Date.now() - 1000),
        encryptedFactorKey: testEncryptedFactorKey,
      });
      mockRepo.findOne.mockResolvedValue(approvedApproval);

      const result = await service.getStatus(testRequestId, testUserId);

      expect(mockRepo.save).not.toHaveBeenCalled();
      expect(result.status).toBe('approved');
    });

    it('should return encryptedFactorKey when present', async () => {
      const approvedApproval = makePendingApproval({
        status: 'approved',
        encryptedFactorKey: testEncryptedFactorKey,
      });
      mockRepo.findOne.mockResolvedValue(approvedApproval);

      const result = await service.getStatus(testRequestId, testUserId);

      expect(result).toEqual({
        status: 'approved',
        encryptedFactorKey: testEncryptedFactorKey,
      });
    });

    it('should omit encryptedFactorKey when null', async () => {
      const approval = makePendingApproval({ encryptedFactorKey: null });
      mockRepo.findOne.mockResolvedValue(approval);

      const result = await service.getStatus(testRequestId, testUserId);

      expect(result).toEqual({ status: 'pending' });
      expect(result).not.toHaveProperty('encryptedFactorKey');
    });
  });

  describe('getPending', () => {
    it('should return mapped pending requests ordered by createdAt DESC', async () => {
      const now = new Date();
      const approval1 = makePendingApproval({
        id: '770e8400-e29b-41d4-a716-446655440002',
        createdAt: new Date('2026-02-15T10:01:00.000Z'),
        expiresAt: new Date(now.getTime() + 4 * 60 * 1000),
      });
      const approval2 = makePendingApproval({
        id: '880e8400-e29b-41d4-a716-446655440003',
        deviceId: 'e'.repeat(64),
        deviceName: 'Firefox on Linux',
        createdAt: new Date('2026-02-15T10:00:00.000Z'),
        expiresAt: new Date(now.getTime() + 3 * 60 * 1000),
      });
      mockRepo.find.mockResolvedValue([approval1, approval2]);

      const result = await service.getPending(testUserId);

      expect(mockRepo.find).toHaveBeenCalledWith({
        where: {
          userId: testUserId,
          status: 'pending',
          expiresAt: expect.anything(),
        },
        order: { createdAt: 'DESC' },
      });
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        requestId: approval1.id,
        deviceId: approval1.deviceId,
        deviceName: approval1.deviceName,
        ephemeralPublicKey: approval1.ephemeralPublicKey,
        createdAt: approval1.createdAt,
        expiresAt: approval1.expiresAt,
      });
      expect(result[1]).toEqual({
        requestId: approval2.id,
        deviceId: approval2.deviceId,
        deviceName: approval2.deviceName,
        ephemeralPublicKey: approval2.ephemeralPublicKey,
        createdAt: approval2.createdAt,
        expiresAt: approval2.expiresAt,
      });
    });

    it('should return empty array when no pending requests exist', async () => {
      mockRepo.find.mockResolvedValue([]);

      const result = await service.getPending(testUserId);

      expect(result).toEqual([]);
    });
  });

  describe('respond', () => {
    it('should approve request, store encrypted key, and set respondedBy', async () => {
      const approval = makePendingApproval();
      mockRepo.manager.findOne.mockResolvedValue(approval);
      mockRepo.manager.save.mockResolvedValue(approval);

      const dto: RespondApprovalDto = {
        action: 'approve',
        encryptedFactorKey: testEncryptedFactorKey,
        respondedByDeviceId: testRespondingDeviceId,
      };

      await service.respond(testRequestId, testUserId, dto);

      expect(approval.status).toBe('approved');
      expect(approval.encryptedFactorKey).toBe(testEncryptedFactorKey);
      expect(approval.respondedBy).toBe(testRespondingDeviceId);
      expect(mockRepo.manager.save).toHaveBeenCalledWith(approval);
    });

    it('should deny request without setting encrypted key', async () => {
      const approval = makePendingApproval();
      mockRepo.manager.findOne.mockResolvedValue(approval);
      mockRepo.manager.save.mockResolvedValue(approval);

      const dto: RespondApprovalDto = {
        action: 'deny',
        respondedByDeviceId: testRespondingDeviceId,
      };

      await service.respond(testRequestId, testUserId, dto);

      expect(approval.status).toBe('denied');
      expect(approval.encryptedFactorKey).toBeNull();
      expect(approval.respondedBy).toBe(testRespondingDeviceId);
      expect(mockRepo.manager.save).toHaveBeenCalledWith(approval);
    });

    it('should throw NotFoundException when request not found', async () => {
      mockRepo.manager.findOne.mockResolvedValue(null);

      const dto: RespondApprovalDto = {
        action: 'approve',
        encryptedFactorKey: testEncryptedFactorKey,
        respondedByDeviceId: testRespondingDeviceId,
      };

      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        NotFoundException
      );
      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        'Approval request not found'
      );
    });

    it('should throw BadRequestException when already responded to', async () => {
      const approvedApproval = makePendingApproval({ status: 'approved' });
      mockRepo.manager.findOne.mockResolvedValue(approvedApproval);

      const dto: RespondApprovalDto = {
        action: 'approve',
        encryptedFactorKey: testEncryptedFactorKey,
        respondedByDeviceId: testRespondingDeviceId,
      };

      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        BadRequestException
      );
      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        'Approval request has already been responded to'
      );
      expect(mockRepo.manager.save).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException when expired and mark status as expired', async () => {
      const expiredApproval = makePendingApproval({
        expiresAt: new Date(Date.now() - 1000),
      });
      mockRepo.manager.findOne.mockResolvedValue(expiredApproval);
      mockRepo.manager.save.mockResolvedValue(expiredApproval);

      const dto: RespondApprovalDto = {
        action: 'approve',
        encryptedFactorKey: testEncryptedFactorKey,
        respondedByDeviceId: testRespondingDeviceId,
      };

      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        new BadRequestException('Approval request has expired')
      );
      expect(expiredApproval.status).toBe('expired');
      expect(mockRepo.manager.save).toHaveBeenCalledWith(expiredApproval);
    });

    it('should throw BadRequestException for self-approval (H-02)', async () => {
      const approval = makePendingApproval();
      mockRepo.manager.findOne.mockResolvedValue(approval);

      const dto: RespondApprovalDto = {
        action: 'approve',
        encryptedFactorKey: testEncryptedFactorKey,
        respondedByDeviceId: testDeviceId,
      };

      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        BadRequestException
      );
      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        'A device cannot approve its own request'
      );
      expect(mockRepo.manager.save).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException when approving without encryptedFactorKey (H-03)', async () => {
      const approval = makePendingApproval();
      mockRepo.manager.findOne.mockResolvedValue(approval);

      const dto: RespondApprovalDto = {
        action: 'approve',
        respondedByDeviceId: testRespondingDeviceId,
      };

      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        BadRequestException
      );
      await expect(service.respond(testRequestId, testUserId, dto)).rejects.toThrow(
        'encryptedFactorKey is required when approving'
      );
      expect(mockRepo.manager.save).not.toHaveBeenCalled();
    });
  });

  describe('cancel', () => {
    it('should remove a pending request', async () => {
      const approval = makePendingApproval();
      mockRepo.findOne.mockResolvedValue(approval);
      mockRepo.remove.mockResolvedValue(approval);

      await service.cancel(testRequestId, testUserId);

      expect(mockRepo.findOne).toHaveBeenCalledWith({
        where: { id: testRequestId, userId: testUserId },
      });
      expect(mockRepo.remove).toHaveBeenCalledWith(approval);
    });

    it('should throw NotFoundException when request not found', async () => {
      mockRepo.findOne.mockResolvedValue(null);

      await expect(service.cancel(testRequestId, testUserId)).rejects.toThrow(NotFoundException);
      await expect(service.cancel(testRequestId, testUserId)).rejects.toThrow(
        'Approval request not found'
      );
      expect(mockRepo.remove).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException when request is not pending', async () => {
      const approvedApproval = makePendingApproval({ status: 'approved' });
      mockRepo.findOne.mockResolvedValue(approvedApproval);

      await expect(service.cancel(testRequestId, testUserId)).rejects.toThrow(NotFoundException);
      await expect(service.cancel(testRequestId, testUserId)).rejects.toThrow(
        'Only pending requests can be cancelled'
      );
      expect(mockRepo.remove).not.toHaveBeenCalled();
    });
  });
});
