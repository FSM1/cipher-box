import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsHexadecimal } from 'class-validator';

export class CreateApprovalDto {
  @ApiProperty({
    description: 'Device ID (SHA-256 hash of device Ed25519 public key)',
    example: 'a1b2c3d4e5f6...',
  })
  @IsString()
  @IsNotEmpty()
  deviceId!: string;

  @ApiProperty({
    description: 'Human-readable device name (e.g., "Chrome on macOS")',
    example: 'Chrome on macOS',
  })
  @IsString()
  @IsNotEmpty()
  deviceName!: string;

  @ApiProperty({
    description: 'Ephemeral secp256k1 public key in hex (uncompressed) for ECIES key exchange',
    example: '04abc123...',
  })
  @IsString()
  @IsNotEmpty()
  @IsHexadecimal()
  ephemeralPublicKey!: string;
}
