import { ApiProperty } from '@nestjs/swagger';

export class TokenResponseDto {
  @ApiProperty({
    description: 'New JWT access token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken!: string;
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
};
