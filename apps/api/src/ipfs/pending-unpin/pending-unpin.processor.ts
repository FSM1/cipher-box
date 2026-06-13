import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { Job } from 'bullmq';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IPFS_PROVIDER, IpfsProvider } from '../providers';
import { MetricsService } from '../../metrics/metrics.service';

const BATCH_SIZE = 50;

// Bound the Kubo pin/ls call so a network hang can't stall the drift job forever.
const KUBO_PIN_LS_TIMEOUT_MS = 30_000;

@Processor('pending-unpins')
export class PendingUnpinProcessor extends WorkerHost {
  private readonly logger = new Logger(PendingUnpinProcessor.name);
  private readonly apiUrl: string;

  constructor(
    @InjectRepository(PendingUnpin)
    private readonly pendingUnpinRepository: Repository<PendingUnpin>,
    @InjectRepository(PinnedCid)
    private readonly pinnedCidRepository: Repository<PinnedCid>,
    @Inject(IPFS_PROVIDER)
    private readonly ipfsProvider: IpfsProvider,
    private readonly metricsService: MetricsService,
    private readonly configService: ConfigService
  ) {
    super();
    this.apiUrl = this.configService.get<string>('IPFS_LOCAL_API_URL', 'http://localhost:5001');
  }

  async process(job: Job<Record<string, never>>): Promise<void> {
    if (job.name === 'drain-pending-unpins') {
      await this.drainPendingUnpins();
    } else if (job.name === 'drift-report') {
      await this.runDriftReport();
    }
    // Unknown job names are a no-op (future-proofing)
  }

  private async drainPendingUnpins(): Promise<void> {
    const rows = await this.pendingUnpinRepository.find({
      order: { createdAt: 'ASC' },
      take: BATCH_SIZE,
    });

    this.logger.log(`Drain pass: ${rows.length} pending unpin(s) to process`);

    for (const row of rows) {
      try {
        // D-05: Call through provider so "not pinned" is treated as success
        // (LocalProvider.unpinFile swallows "not pinned" at local.provider.ts:94)
        await this.ipfsProvider.unpinFile(row.cid);
        await this.pendingUnpinRepository.delete({ cid: row.cid });
        this.logger.log(`Drained cid=${row.cid}`);
      } catch (err) {
        // Kubo failure: leave row for next run; do not abort the batch
        const message = err instanceof Error ? err.message : String(err);
        this.logger.error(`Failed to drain cid=${row.cid}: ${message}`);
      }
    }

    // D-05: Publish outbox depth gauge after the drain pass
    const remaining = await this.pendingUnpinRepository.count();
    this.metricsService.pendingUnpinsGauge.set(remaining);
  }

  private async runDriftReport(): Promise<void> {
    // D-06: Read-only diff — never deletes anything
    let kuboPins: Set<string>;
    try {
      kuboPins = await this.fetchKuboPins();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Drift report: Kubo pin/ls failed, skipping run: ${message}`);
      return;
    }

    // Build DB accounted set: pinned_cids ∪ pending_unpins
    const [pinnedCidRows, pendingUnpinRows] = await Promise.all([
      this.pinnedCidRepository.find({ select: { cid: true } }),
      this.pendingUnpinRepository.find({ select: { cid: true } }),
    ]);

    const dbCids = new Set<string>([
      ...pinnedCidRows.map((r) => r.cid),
      ...pendingUnpinRows.map((r) => r.cid),
    ]);

    // Report pins that Kubo knows about but our DB does not
    for (const cid of kuboPins) {
      if (!dbCids.has(cid)) {
        this.metricsService.driftOrphanedPinsTotal.inc();
        this.logger.warn(`Drift: unaccounted Kubo pin cid=${cid}`);
      }
    }
  }

  /**
   * Fetch all recursive pins from Kubo using NDJSON line-by-line parsing.
   * Kubo pin/ls returns NDJSON (not a single JSON object) — see Pitfall 6.
   */
  private async fetchKuboPins(): Promise<Set<string>> {
    let response: Response;
    try {
      response = await fetch(`${this.apiUrl}/api/v0/pin/ls?type=recursive`, {
        method: 'POST',
        signal: AbortSignal.timeout(KUBO_PIN_LS_TIMEOUT_MS),
      });
    } catch (err) {
      // AbortSignal.timeout fires a TimeoutError; surface a clear message so the
      // drift job's failure is diagnosable rather than an opaque hang/abort.
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Kubo pin/ls request failed or timed out after ${KUBO_PIN_LS_TIMEOUT_MS}ms: ${message}`
      );
    }

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Kubo pin/ls failed: ${response.status} ${text}`);
    }

    const text = await response.text();
    const pins = new Set<string>();

    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const obj = JSON.parse(trimmed) as { Keys?: Record<string, unknown> };
        if (obj.Keys) {
          for (const cid of Object.keys(obj.Keys)) {
            pins.add(cid);
          }
        }
      } catch {
        // Malformed line — skip and continue (T-42-21 mitigation)
        this.logger.warn(`Drift report: failed to parse Kubo pin/ls line: ${trimmed}`);
      }
    }

    return pins;
  }
}
