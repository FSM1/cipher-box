import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from './user.entity';

/**
 * One member of a rotating refresh-token family.
 *
 * The raw token is a 32-byte random value handed to the client once and
 * stored here only as its SHA-256 hex. Rotation marks the used row
 * (`used_at`) and inserts a successor in the same family; presenting an
 * already-used token is reuse and hard-deletes the whole family. Logout and
 * revocation are hard deletes — used rows persist only within their expiry
 * window, as fuel for reuse detection.
 */
@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('idx_refresh_tokens_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  /** Rotation-chain id: every rotation of one login session shares it. */
  @Index('idx_refresh_tokens_family_id')
  @Column({ name: 'family_id', type: 'uuid' })
  familyId: string;

  /** SHA-256 hex of the raw token; the raw value is never stored. */
  @Column({ name: 'token_hash', type: 'varchar', length: 64, unique: true })
  tokenHash: string;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  /** Set on rotation; a used token presented again means family compromise. */
  @Column({ name: 'used_at', type: 'timestamptz', nullable: true })
  usedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @ManyToOne(() => User, (user) => user.refreshTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
