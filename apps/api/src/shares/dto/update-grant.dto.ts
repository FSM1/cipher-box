import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsBoolean,
  IsNumberString,
  Matches,
  MaxLength,
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

export class UpdateGrantDto {
  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for read access, re-wrapped for the recipient ' +
      'after an owner rotation. The server stores the client-supplied ciphertext as-is.',
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedReadKey must be an even-length hex string',
  })
  @MaxLength(2500)
  encryptedReadKey!: string;

  @ApiProperty({
    description: 'Generation of the root node the rotated key is rooted at (numeric string)',
  })
  @IsNumberString()
  @Validate(IsNonNegativeBigIntConstraint)
  @MaxLength(20)
  rootGeneration!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for write access, set to upgrade a read-only share ' +
      'to write (read->write, D-09). Omit to leave any existing encryptedWriteKey unchanged ' +
      '(e.g. a read-key-rotation-only call). Mutually exclusive with clearEncryptedWriteKey.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedWriteKey must be an even-length hex string',
  })
  @MaxLength(4096)
  @IsOptional()
  encryptedWriteKey?: string;

  @ApiProperty({
    description:
      'When true, clears any existing encryptedWriteKey (write->read downgrade). Omit/false ' +
      'to leave encryptedWriteKey unchanged. Mutually exclusive with encryptedWriteKey.',
    required: false,
    default: false,
  })
  @IsBoolean()
  @IsOptional()
  clearEncryptedWriteKey?: boolean;
}
