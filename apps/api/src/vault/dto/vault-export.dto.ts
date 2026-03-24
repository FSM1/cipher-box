import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

/**
 * Response DTO for vault export.
 * Contains the minimal data needed for independent recovery:
 * root IPNS name + derivation hints.
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

  @ApiPropertyOptional({
    description:
      'Key derivation method used. Always "web3auth" for Core Kit users. Null if user record not found.',
    example: 'web3auth',
    nullable: true,
    type: String,
  })
  derivationMethod!: string | null;
}
