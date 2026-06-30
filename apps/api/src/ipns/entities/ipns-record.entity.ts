import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

@Entity('ipns_records')
// Keyed by ipnsName alone: there is one canonical record per IPNS name, and any
// holder of the name's key may update it (authority is proven by the record's
// signature, not by row ownership). `userId` is retained as a denormalized
// creator marker for listing / TEE enrollment / cleanup only.
@Unique(['ipnsName'])
export class IpnsRecord {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'user_id' })
  userId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user!: User;

  /**
   * IPNS name (k51... CIDv1 format derived from Ed25519 public key)
   */
  @Column({ type: 'varchar', length: 255, name: 'ipns_name' })
  ipnsName!: string;

  /**
   * CID of the latest encrypted folder metadata
   * Null until first publish
   */
  @Column({ type: 'varchar', length: 255, name: 'latest_cid', nullable: true })
  latestCid!: string | null;

  /**
   * IPNS record sequence number for ordering
   * Incremented on each publish
   */
  @Column({ type: 'bigint', name: 'sequence_number', default: 0 })
  sequenceNumber!: string; // TypeORM returns bigint as string

  /**
   * Canonical signed IPNS record bytes for the latest publish.
   * Used to return verifiable signature data on DB-cached resolves.
   */
  @Column({ type: 'bytea', name: 'signed_record', nullable: true })
  signedRecord!: Buffer | null;

  /**
   * ECIES-wrapped Ed25519 private key for TEE republishing
   * Encrypted with TEE public key, only decryptable by TEE
   * Nullable until TEE integration is implemented (Phase 7+)
   */
  @Column({ type: 'bytea', name: 'encrypted_ipns_private_key', nullable: true })
  encryptedIpnsPrivateKey!: Buffer | null;

  /**
   * TEE key epoch the IPNS key was encrypted for
   * Used for key rotation tracking
   * Nullable until TEE integration is implemented (Phase 7+)
   */
  @Column({ type: 'int', name: 'key_epoch', nullable: true })
  keyEpoch!: number | null;

  /**
   * Marks the root folder for this user's vault
   */
  @Column({ type: 'boolean', name: 'is_root', default: false })
  isRoot!: boolean;

  /**
   * When set, this IPNS name has been tombstoned (rotated out).
   * Publish requests on tombstoned records are rejected with 410 Gone.
   * Recovery requires creating a new IPNS name.
   */
  @Column({ type: 'timestamptz', name: 'tombstoned_at', nullable: true })
  tombstonedAt!: Date | null;

  /**
   * Generation counter for the current key-epoch binding.
   * Incremented on key rotation (write-key rotation increments this).
   * TypeORM returns bigint as string — compare with BigInt(row.generation).
   */
  @Column({ type: 'bigint', name: 'generation', default: 0 })
  generation!: string; // TypeORM returns bigint as string

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
