import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';
import { IdentitySubject } from '../../auth/entities/identity-subject.entity';
import { User } from '../../auth/entities/user.entity';

/** Named so the service can tell this violation from every other database fault. */
export const ACCOUNT_DEVICE_PUBLIC_KEY_UNIQUE = 'uq_account_devices_public_key';

/**
 * A device identity key registered to an account (ADR 0009 D4).
 *
 * The row is what makes the rendezvous *bound*: an approval is verified against
 * a key this account proved possession of, so no self-reported identifier is the
 * basis of any check.
 *
 * `identity_subject_id` records the subject bound to the account when the
 * device registered (ADR 0058 D3).
 */
@Entity('account_devices')
@Unique(ACCOUNT_DEVICE_PUBLIC_KEY_UNIQUE, ['publicKey'])
@Index('idx_account_devices_user_id', ['userId'])
@Index('idx_account_devices_identity_subject', ['identitySubjectId'])
export class AccountDevice {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  /** The `identity_subjects` subject this device authenticated through. */
  @Column({ name: 'identity_subject_id', type: 'uuid' })
  identitySubjectId: string;

  @ManyToOne(() => IdentitySubject)
  @JoinColumn({ name: 'identity_subject_id' })
  identitySubject: IdentitySubject;

  /** Raw Ed25519 public key, lowercase hex. Unique account-wide and globally. */
  @Column({ name: 'public_key', type: 'varchar', length: 64 })
  publicKey: string;

  /** Member-supplied display label; context for the approval prompt, never evidence. */
  @Column({ name: 'label', type: 'varchar', length: 64, nullable: true })
  label: string | null;

  @Column({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'last_seen_at', type: 'timestamptz' })
  lastSeenAt: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
