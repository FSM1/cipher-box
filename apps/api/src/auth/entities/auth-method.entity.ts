import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './user.entity';

export type AuthMethodType =
  | 'google'
  | 'apple'
  | 'github'
  | 'email_passwordless'
  | 'external_wallet';

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

  @Column('timestamp', { nullable: true })
  lastUsedAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @ManyToOne(() => User, (user) => user.authMethods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user!: User;
}
