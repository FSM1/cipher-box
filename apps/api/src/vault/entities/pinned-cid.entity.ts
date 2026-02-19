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
import { User } from '../../auth/entities/user.entity';

@Entity('pinned_cids')
@Unique(['userId', 'cid'])
export class PinnedCid {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'user_id' })
  userId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user!: User;

  /**
   * IPFS CID (Content Identifier) for the pinned content
   * CIDv1 format (base32 encoded)
   */
  @Column({ type: 'varchar', length: 255 })
  cid!: string;

  /**
   * Size of the pinned content in bytes
   * Used for quota tracking (500 MiB limit)
   */
  @Column({ type: 'bigint', name: 'size_bytes' })
  sizeBytes!: string; // TypeORM returns bigint as string

  @CreateDateColumn({ name: 'pinned_at' })
  pinnedAt!: Date;
}
