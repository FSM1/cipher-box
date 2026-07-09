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

// Plain unique constraint — hard-delete on revoke means no revoked rows coexist (D-11)
@Entity('shares')
@Unique(['sharerId', 'recipientId', 'rootNodeId'])
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

  /**
   * ECIES-wrapped root readKey for read access.
   * Server never sees plaintext (zero-knowledge, CLAUDE.md rule 6).
   */
  @Column({ type: 'bytea', name: 'encrypted_read_key' })
  encryptedReadKey!: Buffer;

  /**
   * ECIES-wrapped root writeKey for write access.
   * NULL for read-only shares. Presence signals write grant (D-09).
   */
  @Column({ type: 'bytea', name: 'encrypted_write_key', nullable: true })
  encryptedWriteKey!: Buffer | null;

  /**
   * UUID of the root shared node (folder or file).
   */
  @Column({ type: 'uuid', name: 'root_node_id' })
  rootNodeId!: string;

  /**
   * IPNS name (k51...) of the root shared node.
   */
  @Column({ type: 'varchar', length: 255, name: 'share_root_ipns_name' })
  shareRootIpnsName!: string;

  /**
   * Generation of the root node at share creation.
   * TypeORM returns bigint as string.
   */
  @Column({ type: 'bigint', name: 'root_generation', default: 0 })
  rootGeneration!: string;

  /**
   * ECIES-wrapped display name for the recipient's secp256k1 pubkey.
   * Nullable: not required if recipient can derive the name from their filesystem.
   * Server never sees plaintext (CLAUDE.md rule 6).
   */
  @Column({ type: 'bytea', name: 'item_name_encrypted', nullable: true })
  itemNameEncrypted!: Buffer | null;

  /**
   * Recipient has hidden/dismissed this share from their view.
   */
  @Column({ type: 'boolean', name: 'hidden_by_recipient', default: false })
  hiddenByRecipient!: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
