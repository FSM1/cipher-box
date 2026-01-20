import { ApiProperty } from '@nestjs/swagger';

export class LinkMethodDto {
  @ApiProperty({ description: 'Web3Auth ID token from the new auth method' })
  idToken!: string;

  @ApiProperty({ description: 'Login type', enum: ['social', 'external_wallet'] })
  loginType!: 'social' | 'external_wallet';
}

export class AuthMethodResponseDto {
  @ApiProperty()
  id!: string;

  @ApiProperty({ enum: ['google', 'apple', 'github', 'email_passwordless', 'external_wallet'] })
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
  methodId!: string;
}

export class UnlinkMethodResponseDto {
  @ApiProperty()
  success!: boolean;
}
