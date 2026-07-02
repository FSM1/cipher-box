import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
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
}
