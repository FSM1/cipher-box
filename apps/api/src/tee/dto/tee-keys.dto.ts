import { ApiProperty } from '@nestjs/swagger';

/**
 * Response DTO for TEE public keys sent to clients.
 * Clients use the current TEE public key to encrypt IPNS private keys
 * before sending them to the backend for TEE republishing.
 */
export class TeeKeysDto {
  @ApiProperty({
    description: 'Current TEE key epoch number',
    example: 1,
  })
  currentEpoch!: number;

  @ApiProperty({
    description: 'Current epoch TEE secp256k1 public key (uncompressed, 65 bytes, hex-encoded)',
    example: '04a1b2c3d4e5f6...(130 hex characters)',
  })
  currentPublicKey!: string;

  @ApiProperty({
    description: 'Previous TEE key epoch number (null if no rotation has occurred)',
    example: 0,
    nullable: true,
  })
  previousEpoch!: number | null;

  @ApiProperty({
    description:
      'Previous epoch TEE secp256k1 public key (hex-encoded, null if no rotation has occurred)',
    example: null,
    nullable: true,
  })
  previousPublicKey!: string | null;
}
