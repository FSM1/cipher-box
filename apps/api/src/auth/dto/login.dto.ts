import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsIn, IsOptional, IsInt, Min } from 'class-validator';

export type LoginType = 'social' | 'external_wallet' | 'corekit';

export class LoginDto {
  @ApiProperty({
    description: 'JWT ID token from Web3Auth',
    example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString()
  @IsNotEmpty()
  idToken!: string;

  @ApiProperty({
    description:
      'secp256k1 public key for social login, or signature-derived public key for external wallet (ADR-001)',
    example: '0x04...',
  })
  @IsString()
  @IsNotEmpty()
  publicKey!: string;

  @ApiProperty({
    description: 'Type of login used',
    enum: ['social', 'external_wallet'],
    example: 'social',
  })
  @IsString()
  @IsIn(['social', 'external_wallet', 'corekit'])
  loginType!: LoginType;

  @ApiPropertyOptional({
    description:
      'Wallet address for external wallet users. Used for JWT verification. The publicKey field contains the derived key.',
    example: '0x742d35Cc6634C0532925a3b844Bc9e7595f...',
  })
  @IsOptional()
  @IsString()
  walletAddress?: string;

  @ApiPropertyOptional({
    description:
      'Key derivation version for external wallet users (ADR-001). Required for external_wallet loginType.',
    example: 1,
    minimum: 1,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
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

  @ApiPropertyOptional({
    description:
      'Refresh token (only present for desktop clients using X-Client-Type: desktop header)',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  refreshToken?: string;
}

// Internal type for service layer (includes refreshToken for cookie)
export type LoginServiceResult = {
  accessToken: string;
  refreshToken: string;
  isNewUser: boolean;
};
