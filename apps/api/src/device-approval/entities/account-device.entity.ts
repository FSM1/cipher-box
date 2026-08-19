import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/**
 * A device identity key registered to an account (ADR 0009 D4).
 *
 * The row is what makes the rendezvous *bound*: an approval is verified against
 * a key this account proved possession of, so no self-reported identifier is the
 * basis of any check.
 *
 * `identity_subject_id` records which identity the device logged in through. A
 * device that cannot yet reconstruct its key holds only an identity token, so
 * this column is the sole path from that token back to the account whose devices
 * can approve it — without it the pre-reconstruction surface has no account to
 * name. It is deliberately here rather than on `users`, which stays keyed by the
 * derived `publicKey` alone (see `identity-subject.entity.ts`).
 */
@Entity('account_devices')
@Unique('uq_account_devices_public_key', ['publicKey'])
@Index('idx_account_devices_user_id', ['userId'])
@Index('idx_account_devices_identity_subject', ['identitySubjectId'])
export class AccountDevice {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  /** The `identity_subjects` row this device authenticated through. */
  @Column({ name: 'identity_subject_id', type: 'uuid' })
  identitySubjectId: string;

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
