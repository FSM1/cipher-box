import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsIn, IsOptional, Matches, MinLength, MaxLength } from 'class-validator';

export class UpdatePermissionDto {
  @ApiProperty({
    description: 'Permission level for the share',
    enum: ['read', 'write'],
  })
  @IsString()
  @IsIn(['read', 'write'])
  permission!: 'read' | 'write';

  @ApiProperty({
    description:
      'Hex-encoded ECIES ciphertext of IPNS private key. Required when upgrading to write, omitted when downgrading to read.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedIpnsKey must be an even-length hex string',
  })
  @MinLength(64)
  @MaxLength(2048)
  @IsOptional()
  encryptedIpnsKey?: string;
}
