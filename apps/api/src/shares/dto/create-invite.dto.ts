import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsUUID,
  IsOptional,
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

export class CreateInviteDto {
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
    description: 'UUID of the root shared node',
  })
  @IsUUID()
  rootNodeId!: string;

  @ApiProperty({
    description: 'Generation of the root node at invite creation (numeric string)',
    required: false,
    default: '0',
  })
  @IsNumberString()
  @Validate(IsNonNegativeBigIntConstraint)
  @IsOptional()
  rootGeneration?: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES ciphertext of the display name wrapped with the ephemeral public key. ' +
      'Server never sees plaintext (zero-knowledge).',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'itemNameEncrypted must be an even-length hex string',
  })
  @MaxLength(2500)
  @IsOptional()
  itemNameEncrypted?: string;

  @ApiProperty({
    description:
      'Hex-encoded root readKey wrapped with the EPHEMERAL public key via ECIES. ' +
      'Server never sees the ephemeral private key — it lives only in the URL fragment.',
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedReadKey must be an even-length hex string',
  })
  @MinLength(258)
  @MaxLength(2048)
  encryptedReadKey!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for write access wrapped with the EPHEMERAL public key. ' +
      'Omit for read-only invites.',
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
}
