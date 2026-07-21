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

/** Read a positive-integer ms bound, failing closed to `fallback` for unset/garbage. */
function positiveMs(raw: unknown, fallback: number): number {
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
  private readonly staleAlertMs: number;

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
    this.intervalMs = positiveMs(configService.get('REPUBLISHER_INTERVAL_MS'), DEFAULT_INTERVAL_MS);
    this.staleAlertMs = positiveMs(
      configService.get('REPUBLISHER_STALE_ALERT_MS'),
      DEFAULT_STALE_ALERT_MS
    );
  }

  async runOnce(): Promise<void> {
    const now = this.clock.now();
    const names = await this.distinctNames();

    let republished = 0;
    for (const ipnsName of names) {
      if (await this.walkName(ipnsName, now)) {
        republished += 1;
      }
    }

    // One bulk pass for the >24h liveness alert — never per-name.
    const cutoff = new Date(now.getTime() - this.staleAlertMs);
    for (const stale of await this.cache.staleNames(cutoff)) {
      this.alerter.staleRepublish(stale.ipnsName, now.getTime() - stale.baseline.getTime());
    }

    this.alerter.walkComplete(names.length, republished);
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

    // Cache the freshest record; a missing/misread sequence just skips the
    // update (the cache is non-canonical, so a skipped update is harmless).
    const sequence = this.sequenceReader.read(record);
    if (sequence !== null) {
      await this.cache.upsert(ipnsName, record, sequence, now);
    }

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
