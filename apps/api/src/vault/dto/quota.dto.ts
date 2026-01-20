import { ApiProperty } from '@nestjs/swagger';

/**
 * Response DTO for storage quota information
 */
export class QuotaResponseDto {
  @ApiProperty({
    description: 'Current storage usage in bytes',
    example: 104857600,
  })
  usedBytes!: number;

  @ApiProperty({
    description: 'Maximum storage limit in bytes (500 MiB)',
    example: 524288000,
  })
  limitBytes!: number;

  @ApiProperty({
    description: 'Remaining storage in bytes',
    example: 419430400,
  })
  remainingBytes!: number;
}
