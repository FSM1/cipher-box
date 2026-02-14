import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { RefreshToken } from './refresh-token.entity';
import { AuthMethod } from './auth-method.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ unique: true })
  publicKey!: string;

  /**
   * ADR-001: Key derivation version for external wallet users.
   * - Version 1: EIP-712 signature-derived keys (current)
   * - Future versions may use different derivation methods
   *
   * This allows cryptographic agility if vulnerabilities are found.
   * null = social login (no derivation), 1+ = external wallet derivation version
   */
  @Column({ type: 'int', nullable: true, default: null })
  derivationVersion!: number | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens!: RefreshToken[];

  @OneToMany(() => AuthMethod, (authMethod) => authMethod.user)
  authMethods!: AuthMethod[];
}
