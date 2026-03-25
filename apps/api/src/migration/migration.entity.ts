import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

export type MigrationStatus =
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled';

@Entity('pin_migrations')
export class PinMigration {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'user_id' })
  userId!: string;

  @Column({ type: 'varchar', length: 20 })
  status!: MigrationStatus;

  @Column({ type: 'int', name: 'total_cids', default: 0 })
  totalCids!: number;

  @Column({ type: 'int', name: 'migrated_cids', default: 0 })
  migratedCids!: number;

  @Column({ type: 'int', name: 'failed_cids', default: 0 })
  failedCids!: number;

  @Column({ type: 'text', name: 'source_config_encrypted' })
  sourceConfigEncrypted!: string;

  @Column({ type: 'text', name: 'dest_config_encrypted' })
  destConfigEncrypted!: string;

  @Column({ type: 'text', name: 'failed_cid_list', nullable: true })
  failedCidList!: string | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;

  @Column({ type: 'timestamp', name: 'completed_at', nullable: true })
  completedAt!: Date | null;
}
