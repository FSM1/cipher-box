import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export type LoginType = 'social' | 'external_wallet';

export class LoginDto {
  @ApiProperty({
    description: 'JWT ID token from Web3Auth',
    example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  idToken!: string;

  @ApiProperty({
    description:
      'secp256k1 public key for social login, or signature-derived public key for external wallet (ADR-001)',
    example: '0x04...',
  })
  publicKey!: string;

  @ApiProperty({
    description: 'Type of login used',
    enum: ['social', 'external_wallet'],
    example: 'social',
  })
  loginType!: LoginType;

  @ApiPropertyOptional({
    description:
      'Key derivation version for external wallet users (ADR-001). Required for external_wallet loginType.',
    example: 1,
    minimum: 1,
  })
  derivationVersion?: number;
}

export class LoginResponseDto {
  @ApiProperty({
    description: 'JWT access token for API requests',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken!: string;

  @ApiProperty({
    description: 'Whether this is a new user registration',
    example: false,
  })
  isNewUser!: boolean;
}

// Internal type for service layer (includes refreshToken for cookie)
export type LoginServiceResult = {
  accessToken: string;
  refreshToken: string;
  isNewUser: boolean;
};
