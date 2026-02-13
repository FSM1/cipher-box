import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEmail, Length, Matches } from 'class-validator';

export class GoogleLoginDto {
  @ApiProperty({
    description: 'Google OAuth ID token (from Google Sign-In)',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString()
  @IsNotEmpty()
  idToken!: string;
}

export class SendOtpDto {
  @ApiProperty({
    description: 'Email address to send OTP to',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email!: string;
}

export class VerifyOtpDto {
  @ApiProperty({
    description: 'Email address the OTP was sent to',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @ApiProperty({
    description: '6-digit OTP code',
    example: '123456',
  })
  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: 'OTP must be exactly 6 digits' })
  otp!: string;
}

export class IdentityTokenResponseDto {
  @ApiProperty({
    description: 'CipherBox-signed RS256 JWT for Web3Auth custom verifier (sub=userId)',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  idToken!: string;

  @ApiProperty({
    description: 'CipherBox internal user UUID',
    example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  })
  userId!: string;

  @ApiProperty({
    description: 'Whether this is a newly created user',
    example: false,
  })
  isNewUser!: boolean;

  @ApiProperty({
    description: 'Verified email address from the identity provider',
    example: 'user@example.com',
    required: false,
  })
  email?: string;
}

export class SendOtpResponseDto {
  @ApiProperty({
    description: 'Whether the OTP was sent successfully',
    example: true,
  })
  success!: boolean;
}
