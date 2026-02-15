import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsHexadecimal, Length, MaxLength } from 'class-validator';

export class CreateApprovalDto {
  @ApiProperty({
    description: 'Device ID (SHA-256 hash of device Ed25519 public key)',
    example: 'a1b2c3d4e5f6...',
  })
  @IsString()
  @IsNotEmpty()
  @IsHexadecimal()
  @Length(64, 64, { message: 'deviceId must be a 64-char hex SHA-256 hash' })
  deviceId!: string;

  @ApiProperty({
    description: 'Human-readable device name (e.g., "Chrome on macOS")',
    example: 'Chrome on macOS',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  deviceName!: string;

  @ApiProperty({
    description: 'Ephemeral secp256k1 public key in hex (uncompressed) for ECIES key exchange',
    example: '04abc123...',
  })
  @IsString()
  @IsNotEmpty()
  @IsHexadecimal()
  @Length(130, 130, {
    message: 'ephemeralPublicKey must be 130 hex chars (uncompressed secp256k1)',
  })
  ephemeralPublicKey!: string;
}
