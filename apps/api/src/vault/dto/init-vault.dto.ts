import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Matches } from 'class-validator';
import { TeeKeysDto } from '../../tee/dto/tee-keys.dto';

/**
 * Request DTO for vault initialization
 * All byte fields are hex-encoded strings
 */
export class InitVaultDto {
  @ApiProperty({
    description: 'User secp256k1 public key (uncompressed, 65 bytes, hex-encoded)',
    example: '04a1b2c3d4e5f6...(130 hex characters for 65 bytes with 0x04 prefix)',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'ownerPublicKey must be hex-encoded' })
  ownerPublicKey!: string;

  @ApiProperty({
    description: 'ECIES-wrapped root folder AES-256 key (hex-encoded)',
    example: 'a1b2c3d4e5f6...',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[0-9a-fA-F]+$/, {
    message: 'encryptedRootFolderKey must be hex-encoded',
  })
  encryptedRootFolderKey!: string;

  @ApiProperty({
    description: 'ECIES-wrapped Ed25519 IPNS private key (hex-encoded)',
    example: 'a1b2c3d4e5f6...',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[0-9a-fA-F]+$/, {
    message: 'encryptedRootIpnsPrivateKey must be hex-encoded',
  })
  encryptedRootIpnsPrivateKey!: string;

  @ApiProperty({
    description: 'IPNS name (libp2p-key multihash, base58btc or base36)',
    example: 'k51qzi5uqu5dg...',
  })
  @IsString()
  @IsNotEmpty()
  rootIpnsName!: string;
}

/**
 * Response DTO for vault data
 */
export class VaultResponseDto {
  @ApiProperty({
    description: 'Vault UUID',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  id!: string;

  @ApiProperty({
    description: 'User secp256k1 public key (uncompressed, 65 bytes, hex-encoded)',
    example: '04a1b2c3d4e5f6...(130 hex characters for 65 bytes with 0x04 prefix)',
  })
  ownerPublicKey!: string;

  @ApiProperty({
    description: 'ECIES-wrapped root folder AES-256 key (hex-encoded)',
    example: 'a1b2c3d4e5f6...',
  })
  encryptedRootFolderKey!: string;

  @ApiProperty({
    description: 'ECIES-wrapped Ed25519 IPNS private key (hex-encoded)',
    example: 'a1b2c3d4e5f6...',
  })
  encryptedRootIpnsPrivateKey!: string;

  @ApiProperty({
    description: 'IPNS name for root folder',
    example: 'k51qzi5uqu5dg...',
  })
  rootIpnsName!: string;

  @ApiProperty({
    description: 'Vault creation timestamp',
    example: '2026-01-20T12:00:00.000Z',
  })
  createdAt!: Date;

  @ApiProperty({
    description: 'When vault was first used (first file uploaded), null if unused',
    example: '2026-01-20T13:00:00.000Z',
    nullable: true,
  })
  initializedAt!: Date | null;

  @ApiProperty({
    description: 'TEE public keys for IPNS key encryption (null if TEE not initialized)',
    required: false,
    nullable: true,
    type: () => TeeKeysDto,
  })
  teeKeys!: TeeKeysDto | null;
}
