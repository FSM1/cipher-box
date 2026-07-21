import { Column, CreateDateColumn, Entity, PrimaryColumn } from 'typeorm';

/**
 * The non-canonical record cache (blueprint/api.md, Republisher module and
 * recovery). One row per distinct IPNS name, holding the most recent record the
 * republisher resolved from the network.
 *
 * It is a liveness aid, never a data plane: it is consulted by NO client resolve
 * path (clients verify records from the network themselves), it is rebuildable
 * from the network at any time, and it holds opaque signed record bytes the API
 * never decodes or inspects (zero-knowledge). Its ONE integrity rule is
 * monotonicity — a resolved record only replaces the cached one when its
 * `sequence` is strictly greater, so a stale/replayed network answer can never
 * regress the cache to older bytes (enforced race-safe in RecordCacheService via
 * a conditional upsert, not a read-then-write).
 *
 * The name is the primary key (there is exactly one cached record per name), so
 * the conditional upsert can target `ON CONFLICT (ipns_name)` directly.
 */
@Entity('record_cache')
export class RecordCache {
  /** The IPNS name (libp2p-key CID); one cached record per name. */
  @PrimaryColumn({ name: 'ipns_name', type: 'varchar', length: 128 })
  ipnsName: string;

  /** Opaque signed IPNS record bytes; re-PUT verbatim, never decoded server-side. */
  @Column({ name: 'record', type: 'bytea' })
  record: Buffer;

  /** The record's public sequence number; the monotonic regression guard. */
  @Column({ name: 'sequence', type: 'bigint' })
  sequence: string;

  /** Last successful keyless re-PUT; null until the first succeeds. Drives the >24h liveness alert. */
  @Column({ name: 'last_republished_at', type: 'timestamptz', nullable: true })
  lastRepublishedAt: Date | null;

  /** When this name first entered the cache; the staleness baseline before any re-PUT succeeds. */
  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
