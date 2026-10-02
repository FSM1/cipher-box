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
 * - 'email': passwordless email login (secondary; linked to an existing account).
 * - 'test': staging-gated test-login (never available in production).
 */
export const AUTH_METHOD_KINDS = ['identity', 'wallet', 'email', 'test'] as const;

export type AuthMethodKind = (typeof AUTH_METHOD_KINDS)[number];

/** Named so a link can tell a lost race with another link from every other fault. */
export const AUTH_METHOD_IDENTIFIER_UNIQUE = 'uq_auth_methods_kind_identifier';

@Entity('auth_methods')
@Index(AUTH_METHOD_IDENTIFIER_UNIQUE, ['kind', 'identifierHash'], { unique: true })
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
   * publicKey ('identity'), the EIP-55 wallet address ('wallet'), the
   * normalized email address ('email'), or the normalized test handle ('test').
   * The full identifier is stored only as this hash.
   */
  @Column({ name: 'identifier_hash', type: 'varchar', length: 64 })
  identifierHash: string;

  /**
   * The identifier masked for account-settings display: a key or wallet
   * truncated, an email reduced to `m***@domain`.
   */
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
