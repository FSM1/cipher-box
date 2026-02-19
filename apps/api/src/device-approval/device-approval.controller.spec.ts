import { Test, TestingModule } from '@nestjs/testing';
import { ThrottlerGuard } from '@nestjs/throttler';
import { DeviceApprovalController } from './device-approval.controller';
import { DeviceApprovalService } from './device-approval.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CreateApprovalDto } from './dto/create-approval.dto';
import { RespondApprovalDto } from './dto/respond-approval.dto';

describe('DeviceApprovalController', () => {
  let controller: DeviceApprovalController;
  let mockService: {
    createRequest: jest.Mock;
    getStatus: jest.Mock;
    getPending: jest.Mock;
    respond: jest.Mock;
    cancel: jest.Mock;
  };

  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  const testRequestId = '660e8400-e29b-41d4-a716-446655440001';
  const testDeviceId = 'a'.repeat(64);
  const testRespondingDeviceId = 'b'.repeat(64);
  const testEphemeralPublicKey = '04' + 'c'.repeat(128);
  const testEncryptedFactorKey = 'd'.repeat(256);

  const mockRequest = {
    user: { id: testUserId },
  } as unknown as Request & { user: { id: string } };

  beforeEach(async () => {
    mockService = {
      createRequest: jest.fn(),
      getStatus: jest.fn(),
      getPending: jest.fn(),
      respond: jest.fn(),
      cancel: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DeviceApprovalController],
      providers: [
        {
          provide: DeviceApprovalService,
          useValue: mockService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<DeviceApprovalController>(DeviceApprovalController);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('createRequest', () => {
    it('should delegate to service with userId and dto', async () => {
      const dto: CreateApprovalDto = {
        deviceId: testDeviceId,
        deviceName: 'Chrome on macOS',
        ephemeralPublicKey: testEphemeralPublicKey,
      };
      const expected = { requestId: testRequestId };
      mockService.createRequest.mockResolvedValue(expected);

      const result = await controller.createRequest(mockRequest, dto);

      expect(mockService.createRequest).toHaveBeenCalledTimes(1);
      expect(mockService.createRequest).toHaveBeenCalledWith(testUserId, dto);
      expect(result).toEqual(expected);
    });
  });

  describe('getStatus', () => {
    it('should delegate to service with requestId and userId', async () => {
      const expected = { status: 'pending' };
      mockService.getStatus.mockResolvedValue(expected);

      const result = await controller.getStatus(mockRequest, testRequestId);

      expect(mockService.getStatus).toHaveBeenCalledTimes(1);
      expect(mockService.getStatus).toHaveBeenCalledWith(testRequestId, testUserId);
      expect(result).toEqual(expected);
    });

    it('should return encryptedFactorKey when approved', async () => {
      const expected = {
        status: 'approved',
        encryptedFactorKey: testEncryptedFactorKey,
      };
      mockService.getStatus.mockResolvedValue(expected);

      const result = await controller.getStatus(mockRequest, testRequestId);

      expect(result).toEqual(expected);
    });
  });

  describe('getPending', () => {
    it('should delegate to service with userId', async () => {
      const expected = [
        {
          requestId: testRequestId,
          deviceId: testDeviceId,
          deviceName: 'Chrome on macOS',
          ephemeralPublicKey: testEphemeralPublicKey,
          createdAt: new Date('2026-02-15T10:00:00.000Z'),
          expiresAt: new Date('2026-02-15T10:05:00.000Z'),
        },
      ];
      mockService.getPending.mockResolvedValue(expected);

      const result = await controller.getPending(mockRequest);

      expect(mockService.getPending).toHaveBeenCalledTimes(1);
      expect(mockService.getPending).toHaveBeenCalledWith(testUserId);
      expect(result).toEqual(expected);
    });

    it('should return empty array when no pending requests', async () => {
      mockService.getPending.mockResolvedValue([]);

      const result = await controller.getPending(mockRequest);

      expect(result).toEqual([]);
    });
  });

  describe('respond', () => {
    it('should delegate approve action to service with correct args', async () => {
      const dto: RespondApprovalDto = {
        action: 'approve',
        encryptedFactorKey: testEncryptedFactorKey,
        respondedByDeviceId: testRespondingDeviceId,
      };
      mockService.respond.mockResolvedValue(undefined);

      await controller.respond(mockRequest, testRequestId, dto);

      expect(mockService.respond).toHaveBeenCalledTimes(1);
      expect(mockService.respond).toHaveBeenCalledWith(testRequestId, testUserId, dto);
    });

    it('should delegate deny action to service with correct args', async () => {
      const dto: RespondApprovalDto = {
        action: 'deny',
        respondedByDeviceId: testRespondingDeviceId,
      };
      mockService.respond.mockResolvedValue(undefined);

      await controller.respond(mockRequest, testRequestId, dto);

      expect(mockService.respond).toHaveBeenCalledTimes(1);
      expect(mockService.respond).toHaveBeenCalledWith(testRequestId, testUserId, dto);
    });
  });

  describe('cancel', () => {
    it('should delegate to service with requestId and userId', async () => {
      mockService.cancel.mockResolvedValue(undefined);

      await controller.cancel(mockRequest, testRequestId);

      expect(mockService.cancel).toHaveBeenCalledTimes(1);
      expect(mockService.cancel).toHaveBeenCalledWith(testRequestId, testUserId);
    });
  });
});
