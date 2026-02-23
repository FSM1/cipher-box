import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsIn,
  IsArray,
  IsUUID,
  ValidateNested,
  IsOptional,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Type } from 'class-transformer';

class ClaimChildKeyDto {
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
  @IsUUID()
  itemId!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the key re-wrapped for recipient',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(258)
  @MaxLength(2048)
  encryptedKey!: string;
}

export class ClaimInviteDto {
  @ApiProperty({
    description: 'Hex-encoded item key re-wrapped for the recipient via ECIES',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(258)
  @MaxLength(2048)
  encryptedKey!: string;

  @ApiProperty({
    description: 'Re-wrapped child keys for subfolders/files',
    required: false,
    type: [ClaimChildKeyDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ClaimChildKeyDto)
  @IsOptional()
  childKeys?: ClaimChildKeyDto[];
}
