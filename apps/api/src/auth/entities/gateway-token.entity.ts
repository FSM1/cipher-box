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
 * One session's read accelerator token (CONTEXT.md, Accelerator token). Its
 * validity is derived from the refresh family rather than stored here — see
 * `GatewayTokenService.verify`.
 */
@Entity('gateway_tokens')
export class GatewayToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('idx_gateway_tokens_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @Column({ name: 'family_id', type: 'uuid' })
  familyId: string;

  /** SHA-256 hex of the raw token; the raw value is never stored. */
  @Column({ name: 'token_hash', type: 'varchar', length: 64, unique: true })
  tokenHash: string;

  /** Indexed to drive the scheduled expiry sweep's ordered scan. */
  @Index('idx_gateway_tokens_expires_at')
  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @ManyToOne(() => User, (user) => user.gatewayTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
