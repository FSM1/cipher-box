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

  /** SHA-256 hash of the canonical identifier for all auth method types */
  @Column({ name: 'identifier_hash', type: 'varchar', length: 64, nullable: true })
  identifierHash!: string | null;

  /** Human-readable display value for all auth method types */
  @Column({ name: 'identifier_display', type: 'varchar', length: 255, nullable: true })
  identifierDisplay!: string | null;

  @Column('timestamp', { nullable: true })
  lastUsedAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @ManyToOne(() => User, (user) => user.authMethods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user!: User;
}
