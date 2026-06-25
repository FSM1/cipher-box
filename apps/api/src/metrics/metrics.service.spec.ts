import { MetricsService } from './metrics.service';

describe('MetricsService', () => {
  let service: MetricsService;

  // Mock all 4 TypeORM repository injections
  const mockPinnedCidRepo = {
    createQueryBuilder: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    addSelect: jest.fn().mockReturnThis(),
    getRawOne: jest.fn().mockResolvedValue({ count: '0', totalBytes: '0' }),
  };

  const mockFolderIpnsRepo = {
    createQueryBuilder: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    addSelect: jest.fn().mockReturnThis(),
    groupBy: jest.fn().mockReturnThis(),
    getRawMany: jest.fn().mockResolvedValue([]),
  };

  const mockUserRepo = {
    count: jest.fn().mockResolvedValue(0),
  };

  const mockRepublishScheduleRepo = {
    createQueryBuilder: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    addSelect: jest.fn().mockReturnThis(),
    groupBy: jest.fn().mockReturnThis(),
    getRawMany: jest.fn().mockResolvedValue([]),
  };

  beforeEach(() => {
    service = new MetricsService(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mockPinnedCidRepo as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mockFolderIpnsRepo as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mockUserRepo as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mockRepublishScheduleRepo as any
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('ipfsIpnsDuration histogram', () => {
    it('should register cipherbox_ipfs_ipns_duration_seconds histogram', async () => {
      const metric = await service.registry.getSingleMetricAsString(
        'cipherbox_ipfs_ipns_duration_seconds'
      );
      expect(metric).toContain('cipherbox_ipfs_ipns_duration_seconds');
    });

    it('should have operation, result, and source labels', async () => {
      const end = service.ipfsIpnsDuration.startTimer({ operation: 'resolve' });
      end({ result: 'success', source: 'network' });

      const metric = await service.registry.getSingleMetricAsString(
        'cipherbox_ipfs_ipns_duration_seconds'
      );
      expect(metric).toContain('operation="resolve"');
      expect(metric).toContain('result="success"');
      expect(metric).toContain('source="network"');
    });

    it('should accept observations via startTimer and produce valid metric output', async () => {
      const end = service.ipfsIpnsDuration.startTimer({ operation: 'pin' });
      end({ result: 'success', source: '' });

      const metric = await service.registry.getSingleMetricAsString(
        'cipherbox_ipfs_ipns_duration_seconds'
      );
      expect(metric).toContain('# HELP cipherbox_ipfs_ipns_duration_seconds');
      expect(metric).toContain('# TYPE cipherbox_ipfs_ipns_duration_seconds histogram');
      expect(metric).toContain('cipherbox_ipfs_ipns_duration_seconds_count');
      expect(metric).toContain('cipherbox_ipfs_ipns_duration_seconds_sum');
    });

    it('startTimer should return a callable function', () => {
      const end = service.ipfsIpnsDuration.startTimer({ operation: 'cat' });
      expect(typeof end).toBe('function');
    });
  });

  describe('republishBatchDuration histogram', () => {
    it('should register cipherbox_republish_batch_duration_seconds histogram', async () => {
      const metric = await service.registry.getSingleMetricAsString(
        'cipherbox_republish_batch_duration_seconds'
      );
      expect(metric).toContain('cipherbox_republish_batch_duration_seconds');
    });

    it('should have tee_provider and result labels', async () => {
      const end = service.republishBatchDuration.startTimer({ tee_provider: 'mock' });
      end({ result: 'success' });

      const metric = await service.registry.getSingleMetricAsString(
        'cipherbox_republish_batch_duration_seconds'
      );
      expect(metric).toContain('tee_provider="mock"');
      expect(metric).toContain('result="success"');
    });

    it('should accept observations via startTimer and produce valid metric output', async () => {
      const end = service.republishBatchDuration.startTimer({ tee_provider: 'phala' });
      end({ result: 'error' });

      const metric = await service.registry.getSingleMetricAsString(
        'cipherbox_republish_batch_duration_seconds'
      );
      expect(metric).toContain('# HELP cipherbox_republish_batch_duration_seconds');
      expect(metric).toContain('# TYPE cipherbox_republish_batch_duration_seconds histogram');
      expect(metric).toContain('cipherbox_republish_batch_duration_seconds_count');
      expect(metric).toContain('cipherbox_republish_batch_duration_seconds_sum');
    });

    it('startTimer should return a callable function', () => {
      const end = service.republishBatchDuration.startTimer({ tee_provider: 'mock' });
      expect(typeof end).toBe('function');
    });
  });

  describe('existing httpRequestDuration histogram (regression)', () => {
    it('should still register and accept observations', async () => {
      service.httpRequestDuration.observe(
        { method: 'GET', route: '/test', status_code: '200' },
        0.5
      );

      const metric = await service.registry.getSingleMetricAsString(
        'cipherbox_http_request_duration_seconds'
      );
      expect(metric).toContain('cipherbox_http_request_duration_seconds');
      expect(metric).toContain('method="GET"');
      expect(metric).toContain('route="/test"');
    });
  });

  describe('ipnsEntriesTotal gauge zero-state (regression)', () => {
    const collectGauges = () =>
      (service as unknown as { collectGauges: () => Promise<void> }).collectGauges();

    it('emits explicit 0 for every known record type when folder_ipns is empty', async () => {
      mockFolderIpnsRepo.getRawMany.mockResolvedValueOnce([]);

      await collectGauges();

      const metric = await service.registry.getSingleMetricAsString('cipherbox_ipns_entries_total');
      // Without explicit zeroing, an empty table emits no series and Grafana
      // sticks at the last non-zero sample — assert both known types report 0.
      expect(metric).toMatch(
        /cipherbox_ipns_entries_total\{[^}]*record_type="folder"[^}]*\}\s+0\b/
      );
      expect(metric).toMatch(/cipherbox_ipns_entries_total\{[^}]*record_type="file"[^}]*\}\s+0\b/);
    });

    it('overlays real counts while still zeroing absent record types', async () => {
      mockFolderIpnsRepo.getRawMany.mockResolvedValueOnce([{ recordType: 'folder', count: '5' }]);

      await collectGauges();

      const metric = await service.registry.getSingleMetricAsString('cipherbox_ipns_entries_total');
      expect(metric).toMatch(
        /cipherbox_ipns_entries_total\{[^}]*record_type="folder"[^}]*\}\s+5\b/
      );
      expect(metric).toMatch(/cipherbox_ipns_entries_total\{[^}]*record_type="file"[^}]*\}\s+0\b/);
    });
  });
});
