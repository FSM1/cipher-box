import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

@Entity('vaults')
export class Vault {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'uuid', name: 'owner_id' })
  ownerId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'owner_id' })
  owner!: User;

  /**
   * User's secp256k1 public key (uncompressed, 65 bytes)
   * Used for ECIES encryption of vault keys
   */
  @Column({ type: 'bytea', name: 'owner_public_key' })
  ownerPublicKey!: Buffer;

  /**
   * IPNS name (libp2p-key multihash of public key)
   * Used to identify the root folder's IPNS record
   */
  @Column({ type: 'varchar', length: 255, name: 'root_ipns_name' })
  rootIpnsName!: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  /**
   * Set when vault is first used (first file uploaded)
   * Null until vault contains actual content
   */
  @Column({ type: 'timestamp', nullable: true, name: 'initialized_at' })
  initializedAt!: Date | null;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
