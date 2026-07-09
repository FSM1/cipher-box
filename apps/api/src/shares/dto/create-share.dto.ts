import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsUUID,
  IsNumberString,
  Matches,
  MaxLength,
  MinLength,
  Validate,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

// Signed 64-bit upper bound of the bigint "generation" column.
const BIGINT_MAX = 9223372036854775807n;

@ValidatorConstraint({ name: 'isNonNegativeBigInt', async: false })
class IsNonNegativeBigIntConstraint implements ValidatorConstraintInterface {
  validate(value: unknown): boolean {
    if (typeof value !== 'string') return false;
    try {
      const parsed = BigInt(value);
      return parsed >= 0n && parsed <= BIGINT_MAX;
    } catch {
      return false;
    }
  }

  defaultMessage(): string {
    return 'rootGeneration must be an integer between 0 and 9223372036854775807 (signed 64-bit range)';
  }
}

export class CreateShareDto {
  @ApiProperty({
    description: 'Recipient secp256k1 public key (uncompressed, 0x04... format)',
    example: '04abc123...',
  })
  @IsString()
  @Matches(/^(0x)?04[0-9a-fA-F]{128}$/, {
    message:
      'recipientPublicKey must be an uncompressed secp256k1 public key (0x04 + 128 hex chars)',
  })
  recipientPublicKey!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for read access (wrapped root readKey + metadata). ' +
      'Server never sees plaintext (zero-knowledge).',
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedReadKey must be an even-length hex string',
  })
  @MinLength(64)
  @MaxLength(4096)
  encryptedReadKey!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for write access. ' +
      'Presence signals a write grant (D-09). Omit for read-only shares.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedWriteKey must be an even-length hex string',
  })
  @MinLength(64)
  @MaxLength(4096)
  @IsOptional()
  encryptedWriteKey?: string;

  @ApiProperty({
    description: 'UUID of the root shared node (folder or file)',
  })
  @IsUUID()
  rootNodeId!: string;

  @ApiProperty({
    description: 'IPNS name (k51...) of the root shared node',
  })
  @IsString()
  // Canonical CIDv1 libp2p-key validator (matches ipns resolve/tombstone DTOs):
  // k51qzi5uqu5... (base36 PeerID-style) or bafzaa... (base32 IPNS key CID).
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'shareRootIpnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(255)
  shareRootIpnsName!: string;

  @ApiProperty({
    description: 'Generation of the root node at share time (numeric string)',
    required: false,
    default: '0',
  })
  @IsNumberString()
  @Validate(IsNonNegativeBigIntConstraint)
  @IsOptional()
  rootGeneration?: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES ciphertext of the display name wrapped for recipient. ' +
      'Optional: omit if recipient can derive the name from their filesystem.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'itemNameEncrypted must be an even-length hex string',
  })
  @MaxLength(2500)
  @IsOptional()
  itemNameEncrypted?: string;
}
