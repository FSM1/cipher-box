import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class TokenResponseDto {
  @ApiProperty({
    description: 'New JWT access token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken!: string;

  @ApiPropertyOptional({
    description:
      'New refresh token (only present for desktop clients using X-Client-Type: desktop header)',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  refreshToken?: string;

  @ApiPropertyOptional({
    description: 'User email from their most recently used email auth method',
    example: 'user@example.com',
  })
  email?: string;
}

export class DesktopRefreshDto {
  @IsOptional()
  @IsString()
  @ApiPropertyOptional({
    description: 'Refresh token from previous login/refresh (required for desktop clients)',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  refreshToken?: string;
}

export class LogoutResponseDto {
  @ApiProperty({
    description: 'Whether logout was successful',
    example: true,
  })
  success!: boolean;
}

// Internal type for service layer (includes refreshToken for cookie)
export type RefreshServiceResult = {
  accessToken: string;
  refreshToken: string;
  email?: string;
};
