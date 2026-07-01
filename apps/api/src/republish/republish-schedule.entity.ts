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
import { User } from '../auth/entities/user.entity';

@Entity('ipns_republish_schedule')
@Unique(['userId', 'ipnsName'])
@Index(['status', 'nextRepublishAt'])
export class IpnsRepublishSchedule {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'user_id' })
  userId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user!: User;

  /**
   * IPNS name being republished (k51... or bafzaa... format).
   * All signing inputs are sourced from ipns_records via JOIN on this field (D-02 / TEE-03).
   */
  @Column({ type: 'varchar', length: 255, name: 'ipns_name' })
  ipnsName!: string;

  /**
   * When the next republish is due
   */
  @Column({ type: 'timestamp', name: 'next_republish_at' })
  nextRepublishAt!: Date;

  /**
   * When the last successful republish occurred
   */
  @Column({ type: 'timestamp', name: 'last_republish_at', nullable: true })
  lastRepublishAt!: Date | null;

  /**
   * Number of consecutive failures.
   * Resets to 0 on success.
   */
  @Column({ type: 'int', name: 'consecutive_failures', default: 0 })
  consecutiveFailures!: number;

  /**
   * Scheduling status:
   * - 'active': normal republish scheduling
   * - 'retrying': has failed, retrying with backoff
   * - 'stale': exceeded max failures, needs intervention or TEE recovery
   */
  @Column({ type: 'varchar', length: 20, default: 'active' })
  status!: string;

  /**
   * Last failure error message for debugging.
   * NEVER contains key material.
   */
  @Column({ type: 'text', name: 'last_error', nullable: true })
  lastError!: string | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
