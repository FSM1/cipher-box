import { IsString, IsNotEmpty, IsInt, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ConnectionTestRequestDto {
  @ApiProperty({ description: 'ECIES-encrypted provider config (hex-encoded)' })
  @IsString()
  @IsNotEmpty()
  encryptedConfig!: string;

  @ApiProperty({ description: 'TEE epoch for key selection' })
  @IsInt()
  @Min(0)
  epoch!: number;
}

export class ConnectionTestResponseDto {
  @ApiProperty({ description: 'Whether the connection test succeeded' })
  success!: boolean;

  @ApiProperty({ required: false, enum: ['kubo', 'psa'], description: 'Detected protocol' })
  protocol?: 'kubo' | 'psa';

  @ApiProperty({ required: false, description: 'Provider version string' })
  version?: string;

  @ApiProperty({ description: 'Probe latency in milliseconds' })
  latencyMs!: number;

  @ApiProperty({ required: false, description: 'Error message on failure' })
  error?: string;
}
