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

export class InviteChildKeyDto {
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
    description: 'Hex-encoded ECIES ciphertext of the key wrapped with ephemeral public key',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(258)
  @MaxLength(2048)
  encryptedKey!: string;
}

export class CreateInviteDto {
  @ApiProperty({
    description: 'Type of shared item',
    enum: ['folder', 'file'],
  })
  @IsString()
  @IsIn(['folder', 'file'])
  itemType!: 'folder' | 'file';

  @ApiProperty({
    description: 'IPNS name of the shared item',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  ipnsName!: string;

  @ApiProperty({
    description: 'Display name of the shared item',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  itemName!: string;

  @ApiProperty({
    description: 'Hex-encoded item key wrapped with ephemeral public key via ECIES',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(258)
  @MaxLength(2048)
  encryptedKey!: string;

  @ApiProperty({
    description: 'Re-wrapped descendant keys (subfolder/file keys) with ephemeral public key',
    required: false,
    type: [InviteChildKeyDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InviteChildKeyDto)
  @IsOptional()
  encryptedChildKeys?: InviteChildKeyDto[];
}
