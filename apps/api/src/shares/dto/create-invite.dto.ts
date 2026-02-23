import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsIn,
  IsArray,
  ValidateNested,
  IsOptional,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Type } from 'class-transformer';

class InviteChildKeyDto {
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
  @MinLength(1)
  itemId!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the key wrapped with ephemeral public key',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(2)
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
  @MinLength(2)
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
