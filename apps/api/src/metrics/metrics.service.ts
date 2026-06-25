import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as client from 'prom-client';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { IpnsRepublishSchedule } from '../republish/republish-schedule.entity';

/**
 * All `folder_ipns.record_type` values. Seeded to 0 each collection so an empty
 * table reports an explicit `0` per type instead of emitting no series at all —
 * which would otherwise leave Grafana stuck on the last non-zero sample through
 * the Prometheus staleness window (an empty system mis-reporting as N entries).
 */
const IPNS_RECORD_TYPES = ['folder', 'file'] as const;

/**
 * Central Prometheus metrics registry and collector.
 * Exposes both event-driven counters (incremented by controllers/services)
 * and gauge metrics polled from the database every 30 seconds.
 */
@Injectable()
export class MetricsService implements OnModuleInit {
  private readonly logger = new Logger(MetricsService.name);
  readonly registry: client.Registry;
  private collectInterval: ReturnType<typeof setInterval> | null = null;

  // --- Gauges (DB-polled state) ---
  readonly usersTotal: client.Gauge;
  readonly filesTotal: client.Gauge;
  readonly storageBytesTotal: client.Gauge;
  readonly ipnsEntriesTotal: client.Gauge;
  readonly republishScheduleTotal: client.Gauge;

  // --- Counters (event-driven) ---
  readonly fileUploads: client.Counter;
  readonly fileUploadBytes: client.Counter;
  readonly fileDownloads: client.Counter;
  readonly fileUnpins: client.Counter;
  readonly ipnsPublishes: client.Counter;
  readonly ipnsResolves: client.Counter;
  readonly republishRuns: client.Counter;
  readonly republishEntriesProcessed: client.Counter;
  readonly authLogins: client.Counter;

  // --- Counters (delegated routing) ---
  readonly delegatedRoutingRequests: client.Counter;
  readonly delegatedRoutingFallbacks: client.Counter;

  // --- Counters (unpin audit) ---
  readonly unpinCrossUserAttempts: client.Counter;
  readonly driftOrphanedPinsTotal: client.Counter;

  // --- Gauges (unpin outbox) ---
  readonly pendingUnpinsGauge: client.Gauge;

  // --- Histograms ---
  readonly httpRequestDuration: client.Histogram;
  readonly ipfsIpnsDuration: client.Histogram;
  readonly republishBatchDuration: client.Histogram;
  readonly ipnsResolveDuration: client.Histogram;
  readonly ipnsPublishDuration: client.Histogram;

  constructor(
    @InjectRepository(PinnedCid)
    private readonly pinnedCidRepository: Repository<PinnedCid>,
    @InjectRepository(FolderIpns)
    private readonly folderIpnsRepository: Repository<FolderIpns>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(IpnsRepublishSchedule)
    private readonly republishScheduleRepository: Repository<IpnsRepublishSchedule>
  ) {
    this.registry = new client.Registry();
    this.registry.setDefaultLabels({ app: 'cipherbox-api' });

    // Gauges
    this.usersTotal = new client.Gauge({
      name: 'cipherbox_users_total',
      help: 'Total registered users',
      registers: [this.registry],
    });

    this.filesTotal = new client.Gauge({
      name: 'cipherbox_files_total',
      help: 'Total pinned files across all users',
      registers: [this.registry],
    });

    this.storageBytesTotal = new client.Gauge({
      name: 'cipherbox_storage_bytes_total',
      help: 'Total storage used across all users in bytes',
      registers: [this.registry],
    });

    this.ipnsEntriesTotal = new client.Gauge({
      name: 'cipherbox_ipns_entries_total',
      help: 'Total IPNS entries by record type',
      labelNames: ['record_type'],
      registers: [this.registry],
    });

    this.republishScheduleTotal = new client.Gauge({
      name: 'cipherbox_republish_schedule_total',
      help: 'IPNS republish schedule entries by status',
      labelNames: ['status'],
      registers: [this.registry],
    });

    // Counters
    this.fileUploads = new client.Counter({
      name: 'cipherbox_file_uploads_total',
      help: 'Total file uploads',
      registers: [this.registry],
    });

    this.fileUploadBytes = new client.Counter({
      name: 'cipherbox_file_upload_bytes_total',
      help: 'Total bytes uploaded',
      registers: [this.registry],
    });

    this.fileDownloads = new client.Counter({
      name: 'cipherbox_file_downloads_total',
      help: 'Total file downloads',
      registers: [this.registry],
    });

    this.fileUnpins = new client.Counter({
      name: 'cipherbox_file_unpins_total',
      help: 'Total file unpins',
      registers: [this.registry],
    });

    this.ipnsPublishes = new client.Counter({
      name: 'cipherbox_ipns_publishes_total',
      help: 'Total IPNS publishes',
      labelNames: ['type'],
      registers: [this.registry],
    });

    this.ipnsResolves = new client.Counter({
      name: 'cipherbox_ipns_resolves_total',
      help: 'Total IPNS resolves',
      labelNames: ['source'],
      registers: [this.registry],
    });

    this.republishRuns = new client.Counter({
      name: 'cipherbox_republish_runs_total',
      help: 'Total republish cron runs',
      registers: [this.registry],
    });

    this.republishEntriesProcessed = new client.Counter({
      name: 'cipherbox_republish_entries_processed_total',
      help: 'Total republish entries processed',
      labelNames: ['result'],
      registers: [this.registry],
    });

    this.authLogins = new client.Counter({
      name: 'cipherbox_auth_logins_total',
      help: 'Total successful logins',
      labelNames: ['method', 'new_user'],
      registers: [this.registry],
    });

    // Delegated routing counters
    this.delegatedRoutingRequests = new client.Counter({
      name: 'cipherbox_delegated_routing_requests_total',
      help: 'Total delegated routing requests by operation, backend, and outcome',
      labelNames: ['operation', 'backend', 'outcome'],
      registers: [this.registry],
    });

    this.delegatedRoutingFallbacks = new client.Counter({
      name: 'cipherbox_delegated_routing_fallbacks_total',
      help: 'Times the primary routing backend failed and fallback was used',
      labelNames: ['operation'],
      registers: [this.registry],
    });

    // Counters (unpin audit)
    this.unpinCrossUserAttempts = new client.Counter({
      name: 'cipherbox_unpin_cross_user_attempts_total',
      help: 'Unpin requests where the CID exists but belongs to another user',
      registers: [this.registry],
    });

    this.driftOrphanedPinsTotal = new client.Counter({
      name: 'cipherbox_drift_orphaned_pins_total',
      help: 'Kubo pins not tracked in pinned_cids or pending_unpins (drift report)',
      registers: [this.registry],
    });

    // Gauges (unpin outbox)
    this.pendingUnpinsGauge = new client.Gauge({
      name: 'cipherbox_pending_unpins_total',
      help: 'CIDs in the pending_unpins outbox awaiting Kubo pin/rm',
      registers: [this.registry],
    });

    // Histograms
    this.httpRequestDuration = new client.Histogram({
      name: 'cipherbox_http_request_duration_seconds',
      help: 'HTTP request duration in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
      registers: [this.registry],
    });

    this.ipfsIpnsDuration = new client.Histogram({
      name: 'cipherbox_ipfs_ipns_duration_seconds',
      help: 'Duration of IPFS/IPNS operations in seconds',
      labelNames: ['operation', 'result', 'source'] as const,
      buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30],
      registers: [this.registry],
    });

    this.republishBatchDuration = new client.Histogram({
      name: 'cipherbox_republish_batch_duration_seconds',
      help: 'Duration of TEE republish batch processing in seconds',
      labelNames: ['tee_provider', 'result'] as const,
      buckets: [1, 2.5, 5, 10, 15, 30, 45, 60, 90, 120],
      registers: [this.registry],
    });

    this.ipnsResolveDuration = new client.Histogram({
      name: 'cipherbox_ipns_resolve_duration_seconds',
      help: 'IPNS resolve duration in seconds (end-to-end including fallback)',
      labelNames: ['source', 'outcome'],
      buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30],
      registers: [this.registry],
    });

    this.ipnsPublishDuration = new client.Histogram({
      name: 'cipherbox_ipns_publish_duration_seconds',
      help: 'IPNS publish duration to routing provider in seconds',
      labelNames: ['outcome'],
      buckets: [0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60],
      registers: [this.registry],
    });
  }

  async onModuleInit(): Promise<void> {
    // Attempt an immediate collection; log and continue if DB isn't ready yet
    await this.collectGauges().catch((err: unknown) => {
      this.logger.warn(
        `Initial gauge collection failed: ${err instanceof Error ? err.message : String(err)}`
      );
    });
    this.collectInterval = setInterval(() => {
      this.collectGauges().catch((err: unknown) => {
        this.logger.warn(
          `Gauge collection failed: ${err instanceof Error ? err.message : String(err)}`
        );
      });
    }, 30_000);
    this.logger.log('Prometheus metrics initialized (collecting gauges every 30s)');
  }

  onModuleDestroy(): void {
    if (this.collectInterval) {
      clearInterval(this.collectInterval);
    }
  }

  async getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  getContentType(): string {
    return this.registry.contentType;
  }

  private async collectGauges(): Promise<void> {
    const [userCount, fileStats, ipnsByType, republishByStatus] = await Promise.all([
      this.userRepository.count(),
      this.pinnedCidRepository
        .createQueryBuilder('pin')
        .select('COUNT(*)', 'count')
        .addSelect('COALESCE(SUM(pin.size_bytes), 0)', 'totalBytes')
        .getRawOne<{ count: string; totalBytes: string }>(),
      this.folderIpnsRepository
        .createQueryBuilder('ipns')
        .select('ipns.record_type', 'recordType')
        .addSelect('COUNT(*)', 'count')
        .groupBy('ipns.record_type')
        .getRawMany<{ recordType: string; count: string }>(),
      this.republishScheduleRepository
        .createQueryBuilder('sched')
        .select('sched.status', 'status')
        .addSelect('COUNT(*)', 'count')
        .groupBy('sched.status')
        .getRawMany<{ status: string; count: string }>(),
    ]);

    this.usersTotal.set(userCount);
    this.filesTotal.set(parseInt(fileStats?.count ?? '0', 10));
    this.storageBytesTotal.set(parseInt(fileStats?.totalBytes ?? '0', 10));

    // Reset IPNS gauges before setting to avoid stale labels, then seed every
    // known record type to 0 so an empty table reports 0 rather than emitting no
    // series (which makes Grafana "stick" at the last non-zero sample).
    this.ipnsEntriesTotal.reset();
    for (const recordType of IPNS_RECORD_TYPES) {
      this.ipnsEntriesTotal.labels(recordType).set(0);
    }
    for (const row of ipnsByType) {
      this.ipnsEntriesTotal.labels(row.recordType).set(parseInt(row.count, 10));
    }

    // Reset republish gauges before setting
    this.republishScheduleTotal.reset();
    for (const row of republishByStatus) {
      this.republishScheduleTotal.labels(row.status).set(parseInt(row.count, 10));
    }
  }
}
