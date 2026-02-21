import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class UpdateEncryptedKeyDto {
  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the new key wrapped for recipient',
  })
  @IsString()
  encryptedKey!: string;
}
