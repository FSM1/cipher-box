import { ApiProperty } from '@nestjs/swagger';

/**
 * Response DTO for vault configuration
 */
export class VaultConfigResponseDto {
  @ApiProperty({
    description: 'Number of days items are retained in the recycle bin before auto-purge',
    example: 30,
  })
  recycleBinRetentionDays!: number;
}
