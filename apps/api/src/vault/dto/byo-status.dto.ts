import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean } from 'class-validator';

export class SetByoStatusDto {
  @ApiProperty({ description: 'Whether to enable BYO (Bring Your Own) IPFS mode' })
  @IsBoolean()
  isByo!: boolean;
}

export class SetByoStatusResponseDto {
  @ApiProperty({ description: 'Whether the operation succeeded' })
  success!: boolean;
}
