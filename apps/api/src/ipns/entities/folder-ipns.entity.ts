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

@Entity('folder_ipns')
@Unique(['userId', 'ipnsName'])
export class FolderIpns {
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
   * ECIES-wrapped Ed25519 private key for TEE republishing
   * Encrypted with TEE public key, only decryptable by TEE
   */
  @Column({ type: 'bytea', name: 'encrypted_ipns_private_key' })
  encryptedIpnsPrivateKey!: Buffer;

  /**
   * TEE key epoch the IPNS key was encrypted for
   * Used for key rotation tracking
   */
  @Column({ type: 'int', name: 'key_epoch' })
  keyEpoch!: number;

  /**
   * Marks the root folder for this user's vault
   */
  @Column({ type: 'boolean', name: 'is_root', default: false })
  isRoot!: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
