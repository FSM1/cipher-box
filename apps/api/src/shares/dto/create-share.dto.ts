import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsIn, IsArray, ValidateNested, IsOptional } from 'class-validator';
import { Type } from 'class-transformer';

class ChildKeyDto {
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

export class CreateShareDto {
  @ApiProperty({
    description: 'Recipient secp256k1 public key (uncompressed, 0x04... format)',
    example: '04abc123...',
  })
  @IsString()
  recipientPublicKey!: string;

  @ApiProperty({
    description: 'Type of shared item',
    enum: ['folder', 'file'],
  })
  @IsString()
  @IsIn(['folder', 'file'])
  itemType!: 'folder' | 'file';

  @ApiProperty({
    description: 'IPNS name (k51...) of the shared item',
  })
  @IsString()
  ipnsName!: string;

  @ApiProperty({
    description: 'Display name of the shared item',
  })
  @IsString()
  itemName!: string;

  @ApiProperty({
    description: 'Hex-encoded root key wrapped for recipient via ECIES',
  })
  @IsString()
  encryptedKey!: string;

  @ApiProperty({
    description: 'Re-wrapped descendant keys (subfolder/file keys)',
    required: false,
    type: [ChildKeyDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ChildKeyDto)
  @IsOptional()
  childKeys?: ChildKeyDto[];
}
