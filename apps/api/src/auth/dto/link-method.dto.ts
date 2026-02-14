import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsIn, ValidateIf } from 'class-validator';

export class LinkMethodDto {
  @ApiProperty({
    description:
      'CipherBox-issued JWT identity token (required for Google/email, not used for wallet)',
  })
  @ValidateIf((o) => o.loginType !== 'wallet')
  @IsString()
  @IsNotEmpty()
  idToken!: string;

  @ApiProperty({
    description: 'Auth method type to link',
    enum: ['google', 'email', 'wallet'],
  })
  @IsString()
  @IsIn(['google', 'email', 'wallet'])
  loginType!: 'google' | 'email' | 'wallet';

  @ApiPropertyOptional({ description: 'Wallet address (required when loginType is wallet)' })
  @ValidateIf((o) => o.loginType === 'wallet')
  @IsNotEmpty()
  @IsString()
  walletAddress?: string;

  @ApiPropertyOptional({ description: 'SIWE message (required when loginType is wallet)' })
  @ValidateIf((o) => o.loginType === 'wallet')
  @IsNotEmpty()
  @IsString()
  siweMessage?: string;

  @ApiPropertyOptional({ description: 'SIWE signature (required when loginType is wallet)' })
  @ValidateIf((o) => o.loginType === 'wallet')
  @IsNotEmpty()
  @IsString()
  siweSignature?: string;
}

export class AuthMethodResponseDto {
  @ApiProperty()
  id!: string;

  @ApiProperty({ enum: ['google', 'apple', 'github', 'email', 'wallet'] })
  type!: string;

  @ApiProperty({ description: 'Email or wallet address' })
  identifier!: string;

  @ApiProperty({ nullable: true, type: Date })
  lastUsedAt!: Date | null;

  @ApiProperty()
  createdAt!: Date;
}

export class UnlinkMethodDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  methodId!: string;
}

export class UnlinkMethodResponseDto {
  @ApiProperty()
  success!: boolean;
}
