import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique,
} from 'typeorm';
import { Share } from './share.entity';

@Entity('share_keys')
@Unique(['shareId', 'keyType', 'itemId'])
export class ShareKey {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'share_id' })
  shareId!: string;

  @ManyToOne(() => Share, (share) => share.shareKeys, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'share_id' })
  share!: Share;

  /**
   * Type of key stored: 'file' for fileKey, 'folder' for subfolder folderKey.
   */
  @Column({ type: 'varchar', length: 10, name: 'key_type' })
  keyType!: 'file' | 'folder';

  /**
   * UUID of the file or subfolder this key belongs to.
   */
  @Index()
  @Column({ type: 'varchar', length: 255, name: 'item_id' })
  itemId!: string;

  /**
   * The file key or subfolder key wrapped with the recipient's
   * secp256k1 public key via ECIES. Server never sees the plaintext key.
   */
  @Column({ type: 'bytea', name: 'encrypted_key' })
  encryptedKey!: Buffer;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
