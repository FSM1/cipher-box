import {
  Column,
  CreateDateColumn,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { AuthMethod } from './auth-method.entity';
import { GatewayToken } from './gateway-token.entity';
import { RefreshToken } from './refresh-token.entity';

/**
 * Account row. An account IS the Web3Auth-derived secp256k1 identity key
 * (blueprint/api.md, Identity and auth): rows are keyed by `publicKey` and
 * carry the quota-limit override and BYO flag. Quota enforcement itself is a
 * later slice; the columns are part of the users table shape from day one.
 */
@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Compressed secp256k1 public key, lowercase hex (66 chars). */
  @Column({ name: 'public_key', type: 'varchar', length: 130, unique: true })
  publicKey: string;

  /** Per-account quota override in bytes; null = environment default. */
  @Column({ name: 'quota_limit_override', type: 'bigint', nullable: true })
  quotaLimitOverride: string | null;

  /** BYO-IPFS account: pin rows are advisory, never quota-enforced. */
  @Column({ name: 'byo', type: 'boolean', default: false })
  byo: boolean;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => AuthMethod, (authMethod) => authMethod.user)
  authMethods: AuthMethod[];

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => GatewayToken, (gatewayToken) => gatewayToken.user)
  gatewayTokens: GatewayToken[];
}
