import { Column, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/**
 * One reference edge: the account's record `(account, ipnsName)` names `cid`
 * (blueprint/api.md, "Per-referencing-record refcount").
 *
 * `pinned_cids` answers whether the account pins a CID and carries its quota
 * bytes; this table answers which of the account's records still name it. A
 * retire scoped to one record therefore cannot unpin a leaf a different live
 * record also names — the case no client can decide, because only the registry
 * holds an account-wide live view and a linearization point.
 */
@Entity('pin_references')
@Index('uq_pin_references_account_name_cid', ['accountId', 'ipnsName', 'cid'], { unique: true })
// Serves the "does any record of this account still name these CIDs" recount
// that decides whether the pin row may go.
@Index('idx_pin_references_account_cid', ['accountId', 'cid'])
export class PinReference {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Owning account (users.id). Rows cascade-delete with the account. */
  @Column({ name: 'account_id', type: 'uuid' })
  accountId: string;

  /** The referencing record's IPNS name. */
  @Column({ name: 'ipns_name', type: 'varchar', length: 128 })
  ipnsName: string;

  /** The CID that record names. */
  @Column({ name: 'cid', type: 'varchar', length: 256 })
  cid: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'account_id' })
  account: User;
}
