import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm';

@Entity('pending_unpins')
export class PendingUnpin {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 255 })
  cid!: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
