import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as client from 'prom-client';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { IpnsRepublishSchedule } from '../republish/republish-schedule.entity';

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

  // --- Histograms ---
  readonly httpRequestDuration: client.Histogram;

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
      help: 'Total authentication attempts',
      labelNames: ['method', 'new_user'],
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
  }

  async onModuleInit(): Promise<void> {
    // Collect gauge values immediately, then every 30 seconds
    await this.collectGauges();
    this.collectInterval = setInterval(() => {
      this.collectGauges().catch((err) => {
        this.logger.warn(`Gauge collection failed: ${err.message}`);
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

    // Reset IPNS gauges before setting to avoid stale labels
    this.ipnsEntriesTotal.reset();
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
