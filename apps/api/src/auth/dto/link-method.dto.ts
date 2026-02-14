import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsIn, IsOptional } from 'class-validator';

export class LinkMethodDto {
  @ApiProperty({ description: 'CipherBox-issued JWT identity token for the new auth method' })
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
  @IsOptional()
  @IsString()
  walletAddress?: string;

  @ApiPropertyOptional({ description: 'SIWE message (required when loginType is wallet)' })
  @IsOptional()
  @IsString()
  siweMessage?: string;

  @ApiPropertyOptional({ description: 'SIWE signature (required when loginType is wallet)' })
  @IsOptional()
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
