import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export type LoginType = 'corekit';

export class LoginDto {
  @ApiProperty({
    description: 'CipherBox-issued JWT identity token',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString()
  @IsNotEmpty()
  idToken!: string;

  @ApiProperty({
    description: 'secp256k1 public key exported from Core Kit after loginWithJWT',
    example: '0x04...',
  })
  @IsString()
  @IsNotEmpty()
  publicKey!: string;

  @ApiProperty({
    description: 'Type of login used (always corekit)',
    enum: ['corekit'],
    example: 'corekit',
  })
  @IsString()
  @IsIn(['corekit'])
  loginType!: LoginType;
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
