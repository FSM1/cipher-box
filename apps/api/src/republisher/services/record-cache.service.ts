import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RecordCache } from '../entities/record-cache.entity';

export interface CacheUpsertResult {
  /** True if the record was stored (first insert or a strictly-newer update). */
  stored: boolean;
}

/**
 * The non-canonical record cache store (blueprint/api.md). It is written only by
 * the republisher walk and read only by the recovery endpoint — never on any
 * client resolve path. Records are opaque signed bytes; this service never
 * decodes them.
 */
@Injectable()
export class RecordCacheService {
  constructor(
    @InjectRepository(RecordCache)
    private readonly repository: Repository<RecordCache>
  ) {}

  /**
   * Store a resolved record for a name, refusing any sequence regression.
   *
   * The refusal is a single atomic statement — a conditional upsert whose
   * `WHERE excluded.sequence > record_cache.sequence` runs under the row lock
   * `ON CONFLICT` already takes — so two concurrent writers of different
   * sequences can never let the older one win, and no read-then-write window
   * exists to race (blueprint/api.md: refuses sequence-regressing records). A
   * strictly-greater comparison also makes re-storing the same sequence an
   * idempotent no-op. `RETURNING` yields a row only when the write took, so an
   * empty result set means the guard refused a stale/equal sequence.
   */
  async upsert(
    ipnsName: string,
    record: Buffer,
    sequence: bigint,
    now: Date
  ): Promise<CacheUpsertResult> {
    const rows: unknown[] = await this.repository.query(
      `INSERT INTO record_cache (ipns_name, record, sequence, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (ipns_name) DO UPDATE
         SET record = EXCLUDED.record, sequence = EXCLUDED.sequence
         WHERE EXCLUDED.sequence > record_cache.sequence
       RETURNING ipns_name`,
      [ipnsName, record, sequence.toString(), now]
    );
    return { stored: rows.length > 0 };
  }

  /** Stamp a successful keyless re-PUT so the >24h liveness alert resets. */
  async markRepublished(ipnsName: string, now: Date): Promise<void> {
    await this.repository.update({ ipnsName }, { lastRepublishedAt: now });
  }

  /**
   * Names whose last successful re-PUT (or first-seen, if never re-PUT) predates
   * `cutoff` — the >24h liveness alert set. One bulk query, never per-name: the
   * baseline is `COALESCE(last_republished_at, created_at)` so a name that has
   * never been re-PUT ages from when it entered the cache.
   */
  async staleNames(cutoff: Date): Promise<{ ipnsName: string; baseline: Date }[]> {
    const rows: { ipns_name: string; baseline: Date }[] = await this.repository.query(
      `SELECT ipns_name, COALESCE(last_republished_at, created_at) AS baseline
       FROM record_cache
       WHERE COALESCE(last_republished_at, created_at) < $1`,
      [cutoff]
    );
    return rows.map((row) => ({ ipnsName: row.ipns_name, baseline: new Date(row.baseline) }));
  }

  /**
   * Fetch cached record bytes by name for the recovery endpoint; null if the
   * name was never cached. The bytes may be past their EOL — recovery is
   * explicitly the revival aid after a liveness lapse.
   */
  async fetch(ipnsName: string): Promise<Buffer | null> {
    const row = await this.repository.findOne({ where: { ipnsName } });
    return row ? row.record : null;
  }
}
