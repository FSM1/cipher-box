import { ApiProperty } from '@nestjs/swagger';

export class RefreshDto {
  @ApiProperty({
    description: 'Refresh token to exchange for new tokens',
    example: 'a1b2c3d4e5f6...',
  })
  refreshToken!: string;
}

export class TokenResponseDto {
  @ApiProperty({
    description: 'New JWT access token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken!: string;

  @ApiProperty({
    description: 'New refresh token (old one is invalidated)',
    example: 'b2c3d4e5f6g7...',
  })
  refreshToken!: string;
}

export class LogoutResponseDto {
  @ApiProperty({
    description: 'Whether logout was successful',
    example: true,
  })
  success!: boolean;
}
