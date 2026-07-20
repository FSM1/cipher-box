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
 * How an account authenticates.
 *
 * - 'identity': challenge-signature login against the secp256k1 identity key
 *   (the primary method; implicit account creation happens here).
 * - 'wallet': SIWE wallet login (secondary; linked to an existing account).
 * - 'test': staging-gated test-login (never available in production).
 */
export type AuthMethodKind = 'identity' | 'wallet' | 'test';

@Entity('auth_methods')
@Index('uq_auth_methods_kind_identifier', ['kind', 'identifierHash'], { unique: true })
export class AuthMethod {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('idx_auth_methods_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @Column({ name: 'kind', type: 'varchar', length: 16 })
  kind: AuthMethodKind;

  /**
   * SHA-256 hex of the canonical identifier — the compressed identity
   * publicKey ('identity'), the EIP-55 wallet address ('wallet'), or the
   * normalized test handle ('test'). Plaintext identifiers are never stored.
   */
  @Column({ name: 'identifier_hash', type: 'varchar', length: 64 })
  identifierHash: string;

  /** Truncated human-readable identifier for account-settings display. */
  @Column({ name: 'identifier_display', type: 'varchar', length: 255, nullable: true })
  identifierDisplay: string | null;

  @Column({ name: 'last_used_at', type: 'timestamptz', nullable: true })
  lastUsedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @ManyToOne(() => User, (user) => user.authMethods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
