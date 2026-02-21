import { ApiProperty } from '@nestjs/swagger';
import { IsString, Matches, MinLength, MaxLength } from 'class-validator';

export class UpdateEncryptedKeyDto {
  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the new key wrapped for recipient',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(2)
  @MaxLength(1024)
  encryptedKey!: string;
}
