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
 * One name-inventory row: the per-account `(account, ipnsName)` registration
 * that feeds the republisher inventory (blueprint/api.md, Pin/name registry).
 *
 * Membership derives from pin registration on the publish path, never a side
 * channel: register-first, fail-closed — a name's inventory row exists before
 * its first publish, so a live-but-uninventoried name is structurally
 * impossible. Whoever publishes registers under their OWN account; the server
 * is zero-knowledge about the grant graph and authorizes nothing across
 * accounts. Union liveness: a name stays in the republish inventory while any
 * account holds a row for it and leaves when the last row retires — the
 * republisher walks DISTINCT `ipnsName`s across all accounts.
 *
 * The row carries the current head (metadata) CID as a routing hint for the
 * inventory; the head bytes themselves are pinned via a `pinned_cids` row
 * (old + new metadata heads transiently double-count during a rotation —
 * metadata-scale only, accepted).
 */
@Entity('name_inventory')
@Index('uq_name_inventory_account_ipns', ['accountId', 'ipnsName'], { unique: true })
export class NameInventory {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Owning account (users.id). Rows cascade-delete with the account. */
  @Column({ name: 'account_id', type: 'uuid' })
  accountId: string;

  /** The registered IPNS name (libp2p-key CID). Distinct names drive the walk. */
  @Index('idx_name_inventory_ipns_name')
  @Column({ name: 'ipns_name', type: 'varchar', length: 128 })
  ipnsName: string;

  /** Current head (metadata) CID this name points to; null before first publish. */
  @Column({ name: 'head_cid', type: 'varchar', length: 256, nullable: true })
  headCid: string | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'account_id' })
  account: User;
}
