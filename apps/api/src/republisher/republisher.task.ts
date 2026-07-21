import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Clock } from '../common/clock';
import { PeriodicTask } from '../common/worker-scheduler';
import { NameInventory } from '../registry/entities/name-inventory.entity';
import { RecordSequenceReader } from './record-sequence-reader';
import { RecordTransport } from './record-transport';
import { RepublisherAlerter } from './republisher.alerter';
import { RecordCacheService } from './services/record-cache.service';

/** ~12h walk cadence (blueprint/api.md); overridable via REPUBLISHER_INTERVAL_MS. */
const DEFAULT_INTERVAL_MS = 12 * 60 * 60 * 1000;
/** >24h without a successful re-PUT alerts (blueprint/api.md); via REPUBLISHER_STALE_ALERT_MS. */
const DEFAULT_STALE_ALERT_MS = 24 * 60 * 60 * 1000;
/** Hard bound on one sweep (below the cadence); via REPUBLISHER_RUN_TIMEOUT_MS. */
const DEFAULT_RUN_TIMEOUT_MS = 60 * 60 * 1000;
/** In-flight names per sweep so one slow name can't stall the walk; via REPUBLISHER_CONCURRENCY. */
const DEFAULT_CONCURRENCY = 8;
/** The monotonic floor a record with no readable sequence caches at (see walkName). */
const SEQUENCE_FLOOR = 0n;

/** Read a positive integer, failing closed to `fallback` for unset/garbage. */
function positiveInt(raw: unknown, fallback: number): number {
  const value = Number(raw);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

/**
 * The republisher inventory walk (blueprint/api.md, Republisher module and
 * recovery), shaped as a reusable {@link PeriodicTask}. Once per cadence it
 * walks the DISTINCT names in the inventory, resolves each from the network,
 * re-PUTs the same bytes keyless, and caches the freshest record (regression
 * refused). It is a liveness optimization, never a correctness dependency:
 * records carry client-signed 90-day EOLs, so a failed resolve or re-PUT only
 * raises an alert, never a hard error.
 *
 * Every capability is a seam and time is the injected Clock — no direct clock or
 * network call — so the compressed-EOL long-horizon test drives the whole walk
 * over virtual time.
 */
@Injectable()
export class RepublisherTask implements PeriodicTask {
  readonly taskName = 'republisher-walk';
  readonly intervalMs: number;
  readonly runTimeoutMs: number;
  private readonly staleAlertMs: number;
  private readonly concurrency: number;

  constructor(
    @InjectRepository(NameInventory)
    private readonly nameRepository: Repository<NameInventory>,
    private readonly cache: RecordCacheService,
    private readonly transport: RecordTransport,
    private readonly sequenceReader: RecordSequenceReader,
    private readonly alerter: RepublisherAlerter,
    private readonly clock: Clock,
    configService: ConfigService
  ) {
    this.intervalMs = positiveInt(
      configService.get('REPUBLISHER_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS
    );
    this.staleAlertMs = positiveInt(
      configService.get('REPUBLISHER_STALE_ALERT_MS'),
      DEFAULT_STALE_ALERT_MS
    );
    this.runTimeoutMs = positiveInt(
      configService.get('REPUBLISHER_RUN_TIMEOUT_MS'),
      DEFAULT_RUN_TIMEOUT_MS
    );
    this.concurrency = positiveInt(
      configService.get('REPUBLISHER_CONCURRENCY'),
      DEFAULT_CONCURRENCY
    );
  }

  async runOnce(): Promise<void> {
    // No routing endpoint (BYO-only deploy) → the walk can neither resolve nor
    // re-PUT; skip it rather than fire a resolve-failure alert for every name.
    if (!this.transport.configured) {
      return;
    }

    const now = this.clock.now();
    const names = await this.distinctNames();
    const republished = await this.walkAll(names, now);

    // One bulk pass for the >24h liveness alert — never per-name.
    const cutoff = new Date(now.getTime() - this.staleAlertMs);
    for (const stale of await this.cache.staleNames(cutoff)) {
      this.alerter.staleRepublish(stale.ipnsName, now.getTime() - stale.baseline.getTime());
    }

    this.alerter.walkComplete(names.length, republished);
  }

  /**
   * Walk names through a bounded worker pool so one slow name (up to a 10s
   * resolve + 10s re-PUT) can't serialize the whole inventory past the cadence.
   * Single-threaded JS makes the cursor claim atomic between awaits.
   */
  private async walkAll(names: string[], now: Date): Promise<number> {
    let cursor = 0;
    let republished = 0;
    const worker = async (): Promise<void> => {
      while (true) {
        const i = cursor;
        cursor += 1;
        if (i >= names.length) {
          return;
        }
        if (await this.walkName(names[i], now)) {
          republished += 1;
        }
      }
    };
    const workers = Math.min(this.concurrency, names.length);
    await Promise.all(Array.from({ length: workers }, () => worker()));
    return republished;
  }

  /** Resolve → cache → re-PUT one name; returns true iff the keyless re-PUT succeeded. */
  private async walkName(ipnsName: string, now: Date): Promise<boolean> {
    let record: Buffer | null;
    try {
      record = await this.transport.resolve(ipnsName);
    } catch {
      // A transport failure is indistinguishable from absence for a liveness
      // aid — both surface as a resolve-failure alert (orphan / unreachable).
      this.alerter.resolveFailure(ipnsName);
      return false;
    }
    if (record === null) {
      this.alerter.resolveFailure(ipnsName);
      return false;
    }

    // Cache every re-PUT name, floored at 0 when the sequence is unreadable, so a
    // successful re-PUT is never left without a row (which would 404 recovery and
    // drop the name from staleness alerts). CipherBox records carry sequence ≥ 1,
    // so the floor only bites garbage/non-CipherBox bytes — and the monotonic
    // guard means a later real record (≥ 1) always wins over a floored one.
    const sequence = this.sequenceReader.read(record) ?? SEQUENCE_FLOOR;
    await this.cache.upsert(ipnsName, record, sequence, now);

    try {
      await this.transport.republish(ipnsName, record);
    } catch {
      // Re-PUT failed; the staleness backstop alerts if this persists past 24h.
      return false;
    }
    await this.cache.markRepublished(ipnsName, now);
    return true;
  }

  /** The DISTINCT names across all accounts — union liveness (blueprint/api.md). */
  private async distinctNames(): Promise<string[]> {
    const rows: { ipns_name: string }[] = await this.nameRepository
      .createQueryBuilder('n')
      .select('DISTINCT n.ipns_name', 'ipns_name')
      .getRawMany();
    return rows.map((row) => row.ipns_name);
  }
}
