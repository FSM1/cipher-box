import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsIn,
  IsArray,
  ValidateNested,
  Matches,
  MinLength,
  MaxLength,
} from 'class-validator';
import { Type } from 'class-transformer';

class ShareKeyEntryDto {
  @ApiProperty({
    description: 'Type of key: file or folder',
    enum: ['file', 'folder'],
  })
  @IsString()
  @IsIn(['file', 'folder'])
  keyType!: 'file' | 'folder';

  @ApiProperty({
    description: 'UUID of the file or subfolder',
  })
  @IsString()
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, {
    message: 'itemId must be a valid UUID',
  })
  itemId!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the key wrapped for recipient',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(2)
  @MaxLength(1024)
  encryptedKey!: string;
}

export class AddShareKeysDto {
  @ApiProperty({
    description: 'Array of re-wrapped keys to add to the share',
    type: [ShareKeyEntryDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ShareKeyEntryDto)
  keys!: ShareKeyEntryDto[];
}
