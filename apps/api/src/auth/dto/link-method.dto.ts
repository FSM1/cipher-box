import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LinkMethodDto {
  @ApiProperty({ description: 'Web3Auth ID token from the new auth method' })
  @IsString()
  @IsNotEmpty()
  idToken!: string;

  @ApiProperty({ description: 'Login type', enum: ['social', 'external_wallet'] })
  @IsString()
  @IsIn(['social', 'external_wallet'])
  loginType!: 'social' | 'external_wallet';
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
