import { ApiProperty } from '@nestjs/swagger';

export type LoginType = 'social' | 'external_wallet';

export class LoginDto {
  @ApiProperty({
    description: 'JWT ID token from Web3Auth',
    example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  idToken!: string;

  @ApiProperty({
    description: 'secp256k1 public key (social) or Ethereum address (external wallet)',
    example: '0x04...',
  })
  publicKey!: string;

  @ApiProperty({
    description: 'Type of login used',
    enum: ['social', 'external_wallet'],
    example: 'social',
  })
  loginType!: LoginType;
}

export class LoginResponseDto {
  @ApiProperty({
    description: 'JWT access token for API requests',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken!: string;

  @ApiProperty({
    description: 'Refresh token for obtaining new access tokens',
    example: 'a1b2c3d4e5f6...',
  })
  refreshToken!: string;

  @ApiProperty({
    description: 'Whether this is a new user registration',
    example: false,
  })
  isNewUser!: boolean;
}
