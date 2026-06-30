import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { IpnsController } from './ipns.controller';
import { IpnsService } from './ipns.service';
import { MetricsService } from '../metrics/metrics.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { BypassableThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { RequestWithUser } from '../common/types';
import {
  PublishIpnsDto,
  BatchPublishIpnsDto,
  BatchUnenrollIpnsDto,
  ResolveIpnsQueryDto,
  TombstoneIpnsDto,
} from './dto';

describe('IpnsController', () => {
  let controller: IpnsController;
  let ipnsService: jest.Mocked<IpnsService>;

  const ipnsPublishesInc = jest.fn();
  const ipnsResolvesInc = jest.fn();

  const userId = 'user-uuid-123';
  const mockRequest = { user: { id: userId } } as unknown as RequestWithUser;
  const validIpnsName = 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz';

  beforeEach(async () => {
    const mockIpnsService = {
      publishRecord: jest.fn(),
      publishBatch: jest.fn(),
      unenrollBatch: jest.fn(),
      resolveRecord: jest.fn(),
      tombstoneRecord: jest.fn(),
    };

    const mockMetricsService = {
      ipnsPublishes: { inc: ipnsPublishesInc },
      ipnsResolves: { inc: ipnsResolvesInc },
    } as unknown as MetricsService;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IpnsController],
      providers: [
        { provide: IpnsService, useValue: mockIpnsService },
        { provide: MetricsService, useValue: mockMetricsService },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(BypassableThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<IpnsController>(IpnsController);
    ipnsService = module.get(IpnsService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('publishRecord', () => {
    const dto: PublishIpnsDto = {
      ipnsName: validIpnsName,
      record: 'CiQBqKAFp',
      metadataCid: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
    };

    it('delegates to ipnsService.publishRecord with the authenticated user id and returns its result', async () => {
      const serviceResult = { success: true, ipnsName: validIpnsName, sequenceNumber: '1' };
      ipnsService.publishRecord.mockResolvedValue(serviceResult);

      const result = await controller.publishRecord(mockRequest, dto);

      expect(ipnsService.publishRecord).toHaveBeenCalledWith(userId, dto);
      expect(result).toBe(serviceResult);
    });

    it('increments the single-publish metric counter', async () => {
      ipnsService.publishRecord.mockResolvedValue({
        success: true,
        ipnsName: validIpnsName,
        sequenceNumber: '1',
      });

      await controller.publishRecord(mockRequest, dto);

      expect(ipnsPublishesInc).toHaveBeenCalledWith({ type: 'single' });
    });

    it('propagates errors from the service and skips the metric increment', async () => {
      ipnsService.publishRecord.mockRejectedValue(new Error('boom'));

      await expect(controller.publishRecord(mockRequest, dto)).rejects.toThrow('boom');
      expect(ipnsPublishesInc).not.toHaveBeenCalled();
    });
  });

  describe('publishBatch', () => {
    const dto: BatchPublishIpnsDto = {
      records: [
        {
          ipnsName: validIpnsName,
          record: 'CiQBqKAFp',
          metadataCid: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
        },
      ],
    };

    it('delegates to ipnsService.publishBatch with the authenticated user id and returns its result', async () => {
      const serviceResult = {
        results: [{ success: true, ipnsName: validIpnsName, sequenceNumber: '1' }],
        totalSucceeded: 1,
        totalFailed: 0,
      };
      ipnsService.publishBatch.mockResolvedValue(serviceResult);

      const result = await controller.publishBatch(mockRequest, dto);

      expect(ipnsService.publishBatch).toHaveBeenCalledWith(userId, dto);
      expect(result).toBe(serviceResult);
    });

    it('increments the batch-publish counter by the number of succeeded records', async () => {
      ipnsService.publishBatch.mockResolvedValue({
        results: [],
        totalSucceeded: 3,
        totalFailed: 1,
      });

      await controller.publishBatch(mockRequest, dto);

      expect(ipnsPublishesInc).toHaveBeenCalledWith({ type: 'batch' }, 3);
    });
  });

  describe('unenrollBatch', () => {
    const dto: BatchUnenrollIpnsDto = { ipnsNames: [validIpnsName, validIpnsName] };

    it('delegates to ipnsService.unenrollBatch with the user id and the ipns names', async () => {
      ipnsService.unenrollBatch.mockResolvedValue({ totalUnenrolled: 2 });

      await controller.unenrollBatch(mockRequest, dto);

      expect(ipnsService.unenrollBatch).toHaveBeenCalledWith(userId, dto.ipnsNames);
    });

    it('returns the unenrolled count alongside the total requested', async () => {
      ipnsService.unenrollBatch.mockResolvedValue({ totalUnenrolled: 1 });

      const result = await controller.unenrollBatch(mockRequest, dto);

      expect(result).toEqual({ totalUnenrolled: 1, totalRequested: 2 });
    });
  });

  describe('resolveRecord', () => {
    const query: ResolveIpnsQueryDto = { ipnsName: validIpnsName };

    it('throws NotFoundException when the service returns null', async () => {
      ipnsService.resolveRecord.mockResolvedValue(null);

      await expect(controller.resolveRecord(query)).rejects.toThrow(NotFoundException);
      expect(ipnsResolvesInc).not.toHaveBeenCalled();
    });

    it('returns the signature bundle and tracks the network source when full sig data is present', async () => {
      ipnsService.resolveRecord.mockResolvedValue({
        cid: 'bafybeicid',
        sequenceNumber: '5',
        signatureV2: 'sigb64',
        data: 'datab64',
        pubKey: 'pubkeyb64',
      });

      const result = await controller.resolveRecord(query);

      expect(ipnsResolvesInc).toHaveBeenCalledWith({ source: 'network' });
      expect(result).toEqual({
        success: true,
        cid: 'bafybeicid',
        sequenceNumber: '5',
        signatureV2: 'sigb64',
        data: 'datab64',
        pubKey: 'pubkeyb64',
      });
    });

    it('tracks the db_cache source and omits the signature bundle when signatureV2 is absent', async () => {
      ipnsService.resolveRecord.mockResolvedValue({
        cid: 'bafybeicid',
        sequenceNumber: '5',
      });

      const result = await controller.resolveRecord(query);

      expect(ipnsResolvesInc).toHaveBeenCalledWith({ source: 'db_cache' });
      expect(result).toEqual({ success: true, cid: 'bafybeicid', sequenceNumber: '5' });
      expect(result).not.toHaveProperty('signatureV2');
    });

    it('omits the signature bundle when signatureV2 is present but the bundle is incomplete', async () => {
      ipnsService.resolveRecord.mockResolvedValue({
        cid: 'bafybeicid',
        sequenceNumber: '5',
        signatureV2: 'sigb64',
        // data and pubKey missing -> hasSigData is falsy
      });

      const result = await controller.resolveRecord(query);

      // signatureV2 present -> still counted as a network resolve
      expect(ipnsResolvesInc).toHaveBeenCalledWith({ source: 'network' });
      expect(result).toEqual({ success: true, cid: 'bafybeicid', sequenceNumber: '5' });
      expect(result).not.toHaveProperty('signatureV2');
    });
  });

  describe('tombstoneRecord', () => {
    const dto: TombstoneIpnsDto = { ipnsName: validIpnsName };

    it('delegates to ipnsService.tombstoneRecord with the authenticated user id and ipns name', async () => {
      ipnsService.tombstoneRecord.mockResolvedValue(undefined);

      const result = await controller.tombstoneRecord(mockRequest, dto);

      expect(ipnsService.tombstoneRecord).toHaveBeenCalledWith(userId, validIpnsName);
      expect(result).toBeUndefined();
    });

    it('propagates errors from the service', async () => {
      ipnsService.tombstoneRecord.mockRejectedValue(new Error('not owner'));

      await expect(controller.tombstoneRecord(mockRequest, dto)).rejects.toThrow('not owner');
    });
  });
});
