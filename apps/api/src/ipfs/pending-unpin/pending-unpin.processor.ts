import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { DataSource, Repository } from 'typeorm';
import { Job } from 'bullmq';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IPFS_PROVIDER, IpfsProvider } from '../providers';
import { withCidLock, refcountAndMaybeUnpin } from './unpin-helpers';
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
    private readonly configService: ConfigService,
    private readonly dataSource: DataSource
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
        await this.drainRow(row.cid);
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

  /**
   * Process a single outbox row under the same per-CID advisory lock that
   * guardedUnpin uses (vault.service.ts), serializing the refcount re-check +
   * physical unpin against concurrent recordPin/guardedUnpin for the same CID.
   *
   * WR-01: D-02 / WR-01: Run refcount recheck + conditional unpin + outbox delete under
   * the per-CID advisory lock via shared helpers (withCidLock + refcountAndMaybeUnpin).
   * The lock is the first transactional statement, mirroring guardedUnpin (D-04).
   */
  private async drainRow(cid: string): Promise<void> {
    const result = await this.dataSource.transaction((manager) =>
      withCidLock(manager, cid, () => refcountAndMaybeUnpin(manager, cid, this.ipfsProvider))
    );
    if (result.outcome === 'skipped-repinned') {
      // Preserve the distinct skip-path signal so re-pin races stay auditable in prod logs.
      this.logger.log(
        `Drain: skipped unpin for cid=${cid} — CID is re-pinned (refs=${result.refs}); stale outbox row discarded`
      );
    } else {
      this.logger.log(`Drained cid=${cid}`);
    }
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
    // IN-05 disposition: dbCids intentionally includes ALL pinned_cids rows — including
    // BYO advisory rows — to mirror the guardedUnpin refcount semantics (WR-07 accepted:
    // BYO advisory rows block physical unpin, so they must also be counted as "accounted"
    // by the drift report; filtering them out would make the report report false orphans
    // for CIDs that are intentionally retained by a BYO advisory row).
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
        // WR-04 disposition: Counter is intentional here, not a Gauge. Each drift run
        // appends orphan events to a cumulative total so operators can track how many
        // orphan detections have occurred since the process started. A Gauge would
        // require resetting between runs and tracking ephemeral per-run state; cumulative
        // counts are more useful for alerting and trend analysis. (WR-04 accepted per
        // 42-REVIEW author judgement.)
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
