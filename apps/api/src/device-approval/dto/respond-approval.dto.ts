import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsIn, ValidateIf, IsHexadecimal } from 'class-validator';

export class RespondApprovalDto {
  @ApiProperty({
    description: 'Approval action',
    enum: ['approve', 'deny'],
    example: 'approve',
  })
  @IsString()
  @IsIn(['approve', 'deny'])
  action!: 'approve' | 'deny';

  @ApiPropertyOptional({
    description: 'ECIES-encrypted factor key in hex (required when action is approve)',
    example: '04abc123...',
  })
  @ValidateIf((o) => o.action === 'approve')
  @IsString()
  @IsNotEmpty()
  @IsHexadecimal()
  encryptedFactorKey?: string;

  @ApiProperty({
    description: 'Device ID of the responding (approving/denying) device',
    example: 'a1b2c3d4e5f6...',
  })
  @IsString()
  @IsNotEmpty()
  respondedByDeviceId!: string;
}
