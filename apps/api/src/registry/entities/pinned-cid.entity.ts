import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/**
 * One pin row: the per-account `(account, cid, size, advisory)` registration
 * (blueprint/api.md, Pin/name registry). Content CID rows are the quota and
 * union-liveness ledger, independent of any name — the same CID is referenced
 * by many names and re-referenced unchanged across rotations (idempotent
 * upserts).
 *
 * Refcounting is GLOBAL: physical unpin fires only when the LAST account
 * holding a row for a CID retires it (refcount zero) — v1's `guardedUnpin`
 * survives. A shared-scope CID stays pinned while any co-registering account
 * still references it.
 *
 * Quota is a per-account sum over these rows' sizes. Hosted rows
 * (`advisory = false`) are authoritative and gate uploads; a BYO account's
 * rows are `advisory = true` — counted for union liveness and the inventory,
 * never quota-enforced (the bytes live on the user's own provider). Size is
 * established when the hosted upload path pins the bytes; a register that only
 * records CID membership leaves it at 0.
 */
@Entity('pinned_cids')
@Index('uq_pinned_cids_account_cid', ['accountId', 'cid'], { unique: true })
export class PinnedCid {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Owning account (users.id). Rows cascade-delete with the account. */
  @Column({ name: 'account_id', type: 'uuid' })
  accountId: string;

  /** The pinned content CID. Indexed for the global refcount. */
  @Index('idx_pinned_cids_cid')
  @Column({ name: 'cid', type: 'varchar', length: 256 })
  cid: string;

  /** Pinned size in bytes; 0 until the hosted upload path attaches a real size. */
  @Column({ name: 'size', type: 'bigint', default: 0 })
  size: string;

  /** BYO-origin row: counted for liveness/inventory, never quota-enforced. */
  @Column({ name: 'advisory', type: 'boolean', default: false })
  advisory: boolean;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'account_id' })
  account: User;
}
