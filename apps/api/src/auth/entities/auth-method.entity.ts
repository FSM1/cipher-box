import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './user.entity';

export type AuthMethodType = 'google' | 'apple' | 'github' | 'email' | 'wallet';

@Entity('auth_methods')
export class AuthMethod {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column('uuid')
  userId!: string;

  @Column()
  type!: AuthMethodType;

  @Column()
  identifier!: string;

  /** SHA-256 hash of wallet address for fast lookup (wallet auth methods only) */
  @Column({ name: 'identifier_hash', type: 'varchar', length: 64, nullable: true })
  identifierHash!: string | null;

  /** Truncated wallet address for display, e.g. "0xAbCd...1234" (wallet auth methods only) */
  @Column({ name: 'identifier_display', type: 'varchar', length: 15, nullable: true })
  identifierDisplay!: string | null;

  @Column('timestamp', { nullable: true })
  lastUsedAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @ManyToOne(() => User, (user) => user.authMethods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user!: User;
}
