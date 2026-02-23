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

  @Column({ type: 'varchar', length: 44, name: 'token' })
  token!: string;

  @Index()
  @Column({ type: 'uuid', name: 'sharer_id' })
  sharerId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sharer_id' })
  sharer!: User;

  @Column({ type: 'varchar', length: 10, name: 'item_type' })
  itemType!: 'folder' | 'file';

  @Column({ type: 'varchar', length: 255, name: 'ipns_name' })
  ipnsName!: string;

  @Column({ type: 'varchar', length: 255, name: 'item_name' })
  itemName!: string;

  /**
   * The item key wrapped with the EPHEMERAL public key (not recipient's key).
   * Server never sees the ephemeral private key -- it lives only in the URL fragment.
   */
  @Column({ type: 'bytea', name: 'encrypted_key' })
  encryptedKey!: Buffer;

  /**
   * Child keys (subfolder/file keys) wrapped with ephemeral public key.
   * Stored as JSONB for simplicity -- invites are short-lived (7 days).
   */
  @Column({ type: 'jsonb', name: 'encrypted_child_keys', nullable: true })
  encryptedChildKeys!: Array<{
    keyType: 'file' | 'folder';
    itemId: string;
    encryptedKey: string; // hex
  }> | null;

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
