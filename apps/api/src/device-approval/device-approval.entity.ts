import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm';

@Entity('device_approvals')
@Index('idx_device_approvals_user_status', ['userId', 'status'])
export class DeviceApproval {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ name: 'user_id' })
  userId!: string;

  @Column({ name: 'device_id' })
  deviceId!: string;

  @Column({ name: 'device_name' })
  deviceName!: string;

  @Column({ name: 'ephemeral_public_key', type: 'text' })
  ephemeralPublicKey!: string;

  @Column({ default: 'pending' })
  status!: 'pending' | 'approved' | 'denied' | 'expired';

  @Column({ name: 'encrypted_factor_key', type: 'text', nullable: true })
  encryptedFactorKey!: string | null;

  @CreateDateColumn()
  createdAt!: Date;

  @Column({ name: 'expires_at', type: 'timestamp' })
  expiresAt!: Date;

  @Column({ name: 'responded_by', type: 'varchar', nullable: true })
  respondedBy!: string | null;
}
