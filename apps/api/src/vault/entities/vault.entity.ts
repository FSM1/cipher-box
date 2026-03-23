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
   * ECIES-wrapped root folder AES-256 key
   * Encrypted with ownerPublicKey, only decryptable by user's private key
   * Nullable after v2 blob migration (rootFolderKey moves to IPFS vault blob)
   */
  @Column({ type: 'bytea', name: 'encrypted_root_folder_key', nullable: true })
  encryptedRootFolderKey!: Buffer | null;

  /**
   * ECIES-wrapped Ed25519 IPNS private key
   * Used for signing root folder IPNS records
   * Nullable after v2 blob migration (no longer stored server-side)
   */
  @Column({
    type: 'bytea',
    name: 'encrypted_root_ipns_private_key',
    nullable: true,
  })
  encryptedRootIpnsPrivateKey!: Buffer | null;

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

  /**
   * When this vault was migrated to v2 blob format.
   * Null for non-migrated users, timestamp for migrated users.
   */
  @Column({ type: 'timestamp', nullable: true, name: 'migrated_at' })
  migratedAt!: Date | null;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
