import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IPFS_PROVIDER } from '../providers';
import { MetricsService } from '../../metrics/metrics.service';
import { PendingUnpinProcessor } from './pending-unpin.processor';

describe('PendingUnpinProcessor', () => {
  let processor: PendingUnpinProcessor;

  const mockPendingUnpinRepository = {
    find: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  };

  const mockPinnedCidRepository = {
    find: jest.fn(),
    query: jest.fn(),
  };

  const mockIpfsProvider = {
    unpinFile: jest.fn(),
  };

  const mockDriftOrphanedPinsTotal = { inc: jest.fn() };
  const mockPendingUnpinsGauge = { set: jest.fn() };

  const mockMetricsService = {
    driftOrphanedPinsTotal: mockDriftOrphanedPinsTotal,
    pendingUnpinsGauge: mockPendingUnpinsGauge,
  };

  const mockConfigService = {
    get: jest.fn((key: string, defaultVal?: string) => {
      if (key === 'IPFS_LOCAL_API_URL') return 'http://kubo:5001';
      return defaultVal ?? '';
    }),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PendingUnpinProcessor,
        {
          provide: getRepositoryToken(PendingUnpin),
          useValue: mockPendingUnpinRepository,
        },
        {
          provide: getRepositoryToken(PinnedCid),
          useValue: mockPinnedCidRepository,
        },
        {
          provide: IPFS_PROVIDER,
          useValue: mockIpfsProvider,
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    processor = module.get<PendingUnpinProcessor>(PendingUnpinProcessor);

    // Suppress logger noise in tests
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });

  function makeJob(name: string): Job<Record<string, never>> {
    return { name, data: {} } as Job<Record<string, never>>;
  }

  // ---- drain: success ----
  describe('drain: success', () => {
    it('calls unpinFile then deletes the row on success', async () => {
      const row = { id: 'uuid-1', cid: 'cidA', createdAt: new Date() } as PendingUnpin;
      mockPendingUnpinRepository.find.mockResolvedValue([row]);
      mockIpfsProvider.unpinFile.mockResolvedValue(undefined);
      mockPendingUnpinRepository.delete.mockResolvedValue({ affected: 1 });
      mockPendingUnpinRepository.count.mockResolvedValue(0);

      await processor.process(makeJob('drain-pending-unpins'));

      expect(mockIpfsProvider.unpinFile).toHaveBeenCalledWith('cidA');
      expect(mockPendingUnpinRepository.delete).toHaveBeenCalledWith({ cid: 'cidA' });
    });
  });

  // ---- drain: "not pinned" counts as success ----
  describe('drain: "not pinned" is success', () => {
    it('deletes the row when provider resolves (provider already swallows not-pinned)', async () => {
      const row = { id: 'uuid-2', cid: 'cidB', createdAt: new Date() } as PendingUnpin;
      mockPendingUnpinRepository.find.mockResolvedValue([row]);
      // Provider resolves (already handled "not pinned" internally per local.provider.ts:94)
      mockIpfsProvider.unpinFile.mockResolvedValue(undefined);
      mockPendingUnpinRepository.delete.mockResolvedValue({ affected: 1 });
      mockPendingUnpinRepository.count.mockResolvedValue(0);

      await processor.process(makeJob('drain-pending-unpins'));

      expect(mockPendingUnpinRepository.delete).toHaveBeenCalledWith({ cid: 'cidB' });
    });
  });

  // ---- drain: Kubo failure leaves row ----
  describe('drain: failure leaves row', () => {
    it('does NOT delete the row when unpinFile rejects, and batch continues', async () => {
      const row = { id: 'uuid-3', cid: 'cidC', createdAt: new Date() } as PendingUnpin;
      mockPendingUnpinRepository.find.mockResolvedValue([row]);
      mockIpfsProvider.unpinFile.mockRejectedValue(new Error('connection refused'));
      mockPendingUnpinRepository.count.mockResolvedValue(1);

      // Should resolve without throwing
      await expect(processor.process(makeJob('drain-pending-unpins'))).resolves.toBeUndefined();

      // Row must NOT be deleted
      expect(mockPendingUnpinRepository.delete).not.toHaveBeenCalled();
    });
  });

  // ---- drain: gauge published after drain ----
  describe('drain: gauge', () => {
    it('calls pendingUnpinsGauge.set with remaining row count after drain pass', async () => {
      const row = { id: 'uuid-4', cid: 'cidD', createdAt: new Date() } as PendingUnpin;
      mockPendingUnpinRepository.find.mockResolvedValue([row]);
      mockIpfsProvider.unpinFile.mockResolvedValue(undefined);
      mockPendingUnpinRepository.delete.mockResolvedValue({ affected: 1 });
      mockPendingUnpinRepository.count.mockResolvedValue(3);

      await processor.process(makeJob('drain-pending-unpins'));

      expect(mockPendingUnpinsGauge.set).toHaveBeenCalledWith(3);
    });
  });

  // ---- drift: orphan detected ----
  describe('drift: orphan detected', () => {
    it('increments driftOrphanedPinsTotal and warns for unaccounted Kubo pins; no deletes issued', async () => {
      // Kubo pin ls NDJSON: cidA is accounted for (in DB), cidB is unaccounted (orphan)
      const ndjson = [
        JSON.stringify({ Keys: { cidA: { Type: 'recursive' }, cidB: { Type: 'recursive' } } }),
      ].join('\n');

      const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        text: jest.fn().mockResolvedValue(ndjson),
      } as unknown as Response);

      // DB set: pinned_cids has cidA; pending_unpins is empty
      mockPinnedCidRepository.find.mockResolvedValue([
        { cid: 'cidA' } as PinnedCid,
      ]);
      mockPendingUnpinRepository.find.mockResolvedValue([]);

      await processor.process(makeJob('drift-report'));

      expect(mockDriftOrphanedPinsTotal.inc).toHaveBeenCalledTimes(1);

      // Must never call delete or unpinFile in drift path
      expect(mockPendingUnpinRepository.delete).not.toHaveBeenCalled();
      expect(mockIpfsProvider.unpinFile).not.toHaveBeenCalled();

      fetchMock.mockRestore();
    });
  });

  // ---- drift: all accounted ----
  describe('drift: all accounted', () => {
    it('does NOT increment driftOrphanedPinsTotal when all Kubo pins are in DB', async () => {
      const ndjson = JSON.stringify({ Keys: { cidA: { Type: 'recursive' } } });

      const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        text: jest.fn().mockResolvedValue(ndjson),
      } as unknown as Response);

      mockPinnedCidRepository.find.mockResolvedValue([
        { cid: 'cidA' } as PinnedCid,
      ]);
      mockPendingUnpinRepository.find.mockResolvedValue([]);

      await processor.process(makeJob('drift-report'));

      expect(mockDriftOrphanedPinsTotal.inc).not.toHaveBeenCalled();
      expect(mockPendingUnpinRepository.delete).not.toHaveBeenCalled();

      fetchMock.mockRestore();
    });
  });

  // ---- dispatch: routes to correct handler ----
  describe('dispatch', () => {
    it('routes drain-pending-unpins to drainPendingUnpins', async () => {
      mockPendingUnpinRepository.find.mockResolvedValue([]);
      mockPendingUnpinRepository.count.mockResolvedValue(0);

      // Should not throw; find called means drain path was entered
      await processor.process(makeJob('drain-pending-unpins'));
      expect(mockPendingUnpinRepository.find).toHaveBeenCalled();
    });

    it('routes drift-report to runDriftReport', async () => {
      const ndjson = JSON.stringify({ Keys: {} });
      const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        text: jest.fn().mockResolvedValue(ndjson),
      } as unknown as Response);

      mockPinnedCidRepository.find.mockResolvedValue([]);
      mockPendingUnpinRepository.find.mockResolvedValue([]);

      await processor.process(makeJob('drift-report'));
      expect(fetchMock).toHaveBeenCalled();

      fetchMock.mockRestore();
    });

    it('is a no-op for unknown job names', async () => {
      await expect(processor.process(makeJob('unknown-job'))).resolves.toBeUndefined();
      expect(mockPendingUnpinRepository.find).not.toHaveBeenCalled();
      expect(mockPinnedCidRepository.find).not.toHaveBeenCalled();
    });
  });
});
