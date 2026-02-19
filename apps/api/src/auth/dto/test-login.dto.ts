import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEmail } from 'class-validator';

export class TestLoginDto {
  @ApiProperty({ description: 'Email address for the test user' })
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @ApiProperty({ description: 'Secret that must match TEST_LOGIN_SECRET env var' })
  @IsString()
  @IsNotEmpty()
  secret!: string;
}

export class TestLoginResponseDto {
  @ApiProperty({ description: 'JWT access token' })
  accessToken!: string;

  @ApiProperty({ description: 'Refresh token' })
  refreshToken!: string;

  @ApiProperty({ description: 'Whether this is a newly created user' })
  isNewUser!: boolean;

  @ApiProperty({ description: 'Uncompressed secp256k1 public key (hex, 130 chars)' })
  publicKeyHex!: string;

  @ApiProperty({ description: 'secp256k1 private key (hex, 64 chars)' })
  privateKeyHex!: string;
}
