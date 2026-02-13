import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Singleton-row entity tracking the current and previous TEE key epochs.
 * The CipherBox backend uses this to know which TEE public key to give clients
 * for encrypting IPNS private keys, and to manage grace-period key rotation.
 */
@Entity('tee_key_state')
export class TeeKeyState {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  /**
   * Current active TEE key epoch number
   */
  @Column({ type: 'int', name: 'current_epoch', nullable: false })
  currentEpoch!: number;

  /**
   * Current epoch's uncompressed secp256k1 public key (65 bytes, 0x04 prefix)
   */
  @Column({ type: 'bytea', name: 'current_public_key', nullable: false })
  currentPublicKey!: Buffer;

  /**
   * Previous TEE key epoch number (null if no rotation has occurred)
   */
  @Column({ type: 'int', name: 'previous_epoch', nullable: true })
  previousEpoch!: number | null;

  /**
   * Previous epoch's uncompressed secp256k1 public key (65 bytes, 0x04 prefix)
   * Null if no rotation has occurred
   */
  @Column({ type: 'bytea', name: 'previous_public_key', nullable: true })
  previousPublicKey!: Buffer | null;

  /**
   * When the previous epoch's grace period ends.
   * After this timestamp, the previous epoch key is deprecated.
   * Null if no rotation has occurred or grace period already ended.
   */
  @Column({ type: 'timestamp', name: 'grace_period_ends_at', nullable: true })
  gracePeriodEndsAt!: Date | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
