import { ApiProperty } from '@nestjs/swagger';
import { CHILD_KEY_TYPES, type ChildKeyType } from '../types';
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
    description: 'Type of key: file, folder, or file-ipns',
    enum: [...CHILD_KEY_TYPES],
  })
  @IsString()
  @IsIn(CHILD_KEY_TYPES)
  keyType!: ChildKeyType;

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
    description:
      'Hex-encoded ECIES ciphertext of the display name re-wrapped for the recipient. ' +
      'Optional during rollout: legacy clients carry plaintext itemName from the invite.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'itemNameEncrypted must be an even-length hex string',
  })
  @MaxLength(1024)
  @IsOptional()
  itemNameEncrypted?: string;

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
