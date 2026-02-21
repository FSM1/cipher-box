import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { ShareKey } from './share-key.entity';

// Unique constraint is a partial index (WHERE revoked_at IS NULL) created via migration.
// This allows revoked records to coexist with new active shares for the same triple.
@Entity('shares')
export class Share {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'sharer_id' })
  sharerId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sharer_id' })
  sharer!: User;

  @Index()
  @Column({ type: 'uuid', name: 'recipient_id' })
  recipientId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'recipient_id' })
  recipient!: User;

  @Column({ type: 'varchar', length: 10, name: 'item_type' })
  itemType!: 'folder' | 'file';

  @Index()
  @Column({ type: 'varchar', length: 255, name: 'ipns_name' })
  ipnsName!: string;

  /**
   * Display name of the shared item (plaintext).
   * Privacy impact is minimal -- server already knows user IDs involved.
   */
  @Column({ type: 'varchar', length: 255, name: 'item_name' })
  itemName!: string;

  /**
   * The shared item's key (folderKey or parent folderKey) wrapped
   * with the recipient's secp256k1 public key via ECIES.
   * Server never sees the plaintext key.
   */
  @Column({ type: 'bytea', name: 'encrypted_key' })
  encryptedKey!: Buffer;

  /**
   * Recipient has hidden/dismissed this share from their view.
   */
  @Column({ type: 'boolean', name: 'hidden_by_recipient', default: false })
  hiddenByRecipient!: boolean;

  /**
   * Soft-delete timestamp for lazy key rotation.
   * null = active share, timestamp = revoked pending rotation.
   * On next folder modification, sharer rotates folderKey and hard-deletes.
   */
  @Column({ type: 'timestamp', name: 'revoked_at', nullable: true })
  revokedAt!: Date | null;

  @OneToMany(() => ShareKey, (shareKey) => shareKey.share, { cascade: true })
  shareKeys!: ShareKey[];

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
