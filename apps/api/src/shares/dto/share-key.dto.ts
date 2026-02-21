import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsIn, IsArray, ValidateNested } from 'class-validator';
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
  itemId!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the key wrapped for recipient',
  })
  @IsString()
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
