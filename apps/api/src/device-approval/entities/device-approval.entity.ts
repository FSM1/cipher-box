import { Column, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/** Where a rendezvous has got to. Terminal rows are collected once, then gone. */
export type DeviceApprovalStatus = 'pending' | 'approved' | 'denied';

/**
 * One device-approval rendezvous (ADR 0009 D1).
 *
 * `sealed_factor` is opaque ciphertext sealed to `ephemeral_public_key`; the
 * server neither generates nor inspects it. Both signatures are stored as
 * served, so a client can re-check that the ephemeral key it holds is the one
 * the other device signed over.
 */
@Entity('device_approvals')
@Index('idx_device_approvals_user_expires', ['userId', 'expiresAt'])
// Account-less `expires_at` index driving the global sweep's scan;
// idx_device_approvals_user_expires leads with the account and can't drive it.
@Index('idx_device_approvals_expires_at', ['expiresAt'])
export class DeviceApproval {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  /** The requesting device's Ed25519 identity key, lowercase hex. Not yet registered. */
  @Column({ name: 'requester_device_public_key', type: 'varchar', length: 64 })
  requesterDevicePublicKey: string;

  /** Compressed secp256k1 key the factor is to be sealed to, lowercase hex. */
  @Column({ name: 'ephemeral_public_key', type: 'varchar', length: 66 })
  ephemeralPublicKey: string;

  /** Requester's Ed25519 signature over the request payload, lowercase hex. */
  @Column({ name: 'request_signature', type: 'varchar', length: 128 })
  requestSignature: string;

  @Column({ name: 'status', type: 'varchar', length: 16 })
  status: DeviceApprovalStatus;

  /** Opaque sealed factor; set only on approval, never decoded or logged. */
  @Column({ name: 'sealed_factor', type: 'bytea', nullable: true })
  sealedFactor: Buffer | null;

  @Column({ name: 'responder_device_public_key', type: 'varchar', length: 64, nullable: true })
  responderDevicePublicKey: string | null;

  @Column({ name: 'response_signature', type: 'varchar', length: 128, nullable: true })
  responseSignature: string | null;

  @Column({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
