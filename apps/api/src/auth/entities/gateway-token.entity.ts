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
 * One session's read accelerator token — an opaque pseudonym, never a JWT.
 *
 * The row carries no claim the gateway tier could read, so an `Authorization`
 * header observed at that tier (proxy log, caching layer, compromised gateway
 * node) names neither the account nor any capability beyond gateway reads.
 * Identity stays on this side of the lookup.
 *
 * Validity is DERIVED, not coordinated: a token counts only while its refresh
 * family still holds a live, unused row, so logout, reuse detection, and the
 * account hard-delete revoke gateway reads without a second revocation path to
 * keep in step.
 */
@Entity('gateway_tokens')
export class GatewayToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('idx_gateway_tokens_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  /** The refresh family this token's session belongs to. */
  @Index('idx_gateway_tokens_family_id')
  @Column({ name: 'family_id', type: 'uuid' })
  familyId: string;

  /** SHA-256 hex of the raw token; the raw value is never stored. */
  @Column({ name: 'token_hash', type: 'varchar', length: 64, unique: true })
  tokenHash: string;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @ManyToOne(() => User, (user) => user.gatewayTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
