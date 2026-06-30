import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

@Entity('share_invites')
export class ShareInvite {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 44, name: 'token', unique: true })
  token!: string;

  @Index()
  @Column({ type: 'uuid', name: 'sharer_id' })
  sharerId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sharer_id' })
  sharer!: User;

  /**
   * IPNS name (k51...) of the root shared node.
   */
  @Column({ type: 'varchar', length: 255, name: 'root_ipns_name' })
  rootIpnsName!: string;

  /**
   * UUID of the root shared node.
   */
  @Column({ type: 'uuid', name: 'root_node_id' })
  rootNodeId!: string;

  /**
   * Generation of the root node at invite creation.
   * TypeORM returns bigint as string.
   */
  @Column({ type: 'bigint', name: 'root_generation', default: 0 })
  rootGeneration!: string;

  /**
   * ECIES-wrapped display name for the invite's EPHEMERAL public key.
   * Server never sees plaintext (CLAUDE.md rule 6).
   */
  @Column({ type: 'bytea', name: 'item_name_encrypted', nullable: true })
  itemNameEncrypted!: Buffer | null;

  /**
   * The root readKey wrapped with the EPHEMERAL public key.
   * Server never sees the ephemeral private key — it lives only in the URL fragment.
   */
  @Column({ type: 'bytea', name: 'encrypted_key' })
  encryptedKey!: Buffer;

  /**
   * ECIES descriptor ref for write access wrapped with EPHEMERAL public key.
   * NULL for read-only invites.
   */
  @Column({ type: 'bytea', name: 'write_descriptor_ref', nullable: true })
  writeDescriptorRef!: Buffer | null;

  @Column({ type: 'varchar', length: 20, default: 'active' })
  status!: 'active' | 'claimed' | 'revoked';

  @Column({ type: 'integer', name: 'max_claims', default: 1 })
  maxClaims!: number;

  @Column({ type: 'integer', name: 'claim_count', default: 0 })
  claimCount!: number;

  @Column({ type: 'uuid', name: 'claimed_by', nullable: true })
  claimedBy!: string | null;

  @Index()
  @Column({ type: 'timestamp', name: 'expires_at' })
  expiresAt!: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
