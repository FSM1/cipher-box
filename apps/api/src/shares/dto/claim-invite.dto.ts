import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional, Matches, MaxLength, MinLength } from 'class-validator';

export class ClaimInviteDto {
  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for read access re-wrapped for the recipient ' +
      '(claimer re-wraps the root readKey from the ephemeral key to their own pubkey). ' +
      'Server never sees plaintext (zero-knowledge).',
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedReadKey must be an even-length hex string',
  })
  @MinLength(64)
  @MaxLength(4096)
  encryptedReadKey!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for write access re-wrapped for the recipient. ' +
      'Omit for read-only claim.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'encryptedWriteKey must be an even-length hex string',
  })
  @MinLength(64)
  @MaxLength(4096)
  @IsOptional()
  encryptedWriteKey?: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES ciphertext of the display name re-wrapped for the recipient. ' +
      'Optional: omit if recipient can derive the name from their filesystem.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'itemNameEncrypted must be an even-length hex string',
  })
  @MaxLength(2500)
  @IsOptional()
  itemNameEncrypted?: string;
}
