import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

/**
 * Derivation info hints how the user's private key was derived.
 * Helps recovery tools determine how to prompt for key input.
 */
export class DerivationInfoDto {
  @ApiProperty({
    description:
      'Authentication method used to derive the private key. "web3auth" = social login (key managed by Web3Auth MPC), "external-wallet" = EIP-712 signature-derived key.',
    example: 'web3auth',
    enum: ['web3auth', 'external-wallet'],
  })
  method!: 'web3auth' | 'external-wallet';

  @ApiProperty({
    description:
      'Key derivation version for external wallet users. null for social logins, 1+ for external wallet derivation versions.',
    example: 1,
    nullable: true,
  })
  derivationVersion!: number | null;
}

/**
 * Response DTO for vault export.
 * Contains the minimal data needed for independent recovery:
 * root IPNS name + encrypted root keys.
 */
export class VaultExportDto {
  @ApiProperty({
    description: 'Export format identifier',
    example: 'cipherbox-vault-export',
  })
  format!: string;

  @ApiProperty({
    description: 'Export format version',
    example: '1.0',
  })
  version!: string;

  @ApiProperty({
    description: 'ISO 8601 timestamp of when the export was created',
    example: '2026-02-11T12:00:00.000Z',
  })
  exportedAt!: string;

  @ApiProperty({
    description: 'IPNS name for the root folder (libp2p-key multihash)',
    example: 'k51qzi5uqu5dg...',
  })
  rootIpnsName!: string;

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

  @ApiPropertyOptional({
    description: 'Hints about how the private key was derived, to assist recovery tools',
    type: DerivationInfoDto,
    nullable: true,
  })
  derivationInfo!: DerivationInfoDto | null;
}
