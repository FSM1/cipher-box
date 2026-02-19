import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

/**
 * Audit log for TEE key epoch rotations.
 * Records every rotation event for debugging and compliance.
 */
@Entity('tee_key_rotation_log')
export class TeeKeyRotationLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  /**
   * Epoch number before rotation
   */
  @Column({ type: 'int', name: 'from_epoch' })
  fromEpoch!: number;

  /**
   * Epoch number after rotation
   */
  @Column({ type: 'int', name: 'to_epoch' })
  toEpoch!: number;

  /**
   * Public key of the from-epoch (65 bytes uncompressed secp256k1)
   */
  @Column({ type: 'bytea', name: 'from_public_key' })
  fromPublicKey!: Buffer;

  /**
   * Public key of the to-epoch (65 bytes uncompressed secp256k1)
   */
  @Column({ type: 'bytea', name: 'to_public_key' })
  toPublicKey!: Buffer;

  /**
   * Reason for rotation: 'scheduled', 'cvm_update', 'manual'
   */
  @Column({ type: 'varchar', length: 255 })
  reason!: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
