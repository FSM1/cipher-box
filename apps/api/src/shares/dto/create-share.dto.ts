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

export class CreateShareDto {
  @ApiProperty({
    description: 'Recipient secp256k1 public key (uncompressed, 0x04... format)',
    example: '04abc123...',
  })
  @IsString()
  @Matches(/^(0x)?04[0-9a-fA-F]{128}$/, {
    message:
      'recipientPublicKey must be an uncompressed secp256k1 public key (0x04 + 128 hex chars)',
  })
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
  @Matches(/^k[a-z0-9]+$/, { message: 'ipnsName must be a valid IPNS name' })
  @MaxLength(255)
  ipnsName!: string;

  @ApiProperty({
    description: 'Display name of the shared item',
  })
  @IsString()
  @MaxLength(255)
  itemName!: string;

  @ApiProperty({
    description: 'Hex-encoded root key wrapped for recipient via ECIES',
  })
  @IsString()
  @Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedKey must be a hex string' })
  @MinLength(2)
  @MaxLength(1024)
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
