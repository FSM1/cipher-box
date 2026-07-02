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
      'Hex-encoded ECIES descriptor ref for read access, re-wrapped for the recipient ' +
      'after an owner rotation. The server stores the client-supplied ciphertext as-is.',
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'readDescriptorRef must be an even-length hex string',
  })
  @MaxLength(2500)
  readDescriptorRef!: string;

  @ApiProperty({
    description: 'Generation of the root node the rotated descriptor is rooted at (numeric string)',
  })
  @IsNumberString()
  @Validate(IsNonNegativeBigIntConstraint)
  @MaxLength(20)
  rootGeneration!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES descriptor ref for write access, set to upgrade a read-only share ' +
      'to write (read->write, D-09). Omit to leave any existing writeDescriptorRef unchanged ' +
      '(e.g. a read-descriptor-rotation-only call). Mutually exclusive with clearWriteDescriptor.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'writeDescriptorRef must be an even-length hex string',
  })
  @MaxLength(4096)
  @IsOptional()
  writeDescriptorRef?: string;

  @ApiProperty({
    description:
      'When true, clears any existing writeDescriptorRef (write->read downgrade). Omit/false ' +
      'to leave writeDescriptorRef unchanged. Mutually exclusive with writeDescriptorRef.',
    required: false,
    default: false,
  })
  @IsBoolean()
  @IsOptional()
  clearWriteDescriptor?: boolean;
}
