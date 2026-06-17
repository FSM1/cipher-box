import { ApiProperty } from '@nestjs/swagger';
import { IsString, Matches, MaxLength } from 'class-validator';

export class UpdateItemNameDto {
  @ApiProperty({
    description:
      'Hex-encoded ECIES ciphertext of the display name wrapped for the recipient. ' +
      'Used to lazily backfill itemNameEncrypted on legacy shares created before ' +
      'at-rest encryption (decision A2).',
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'itemNameEncrypted must be an even-length hex string',
  })
  @MaxLength(2500)
  itemNameEncrypted!: string;
}
