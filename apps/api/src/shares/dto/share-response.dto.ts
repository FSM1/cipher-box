import { ApiProperty } from '@nestjs/swagger';

export class CreateShareResponseDto {
  @ApiProperty({ description: 'UUID of the created share' })
  shareId!: string;

  @ApiProperty({ description: 'UUID of the recipient user' })
  recipientId!: string;

  @ApiProperty({ enum: ['folder', 'file'] })
  itemType!: string;

  @ApiProperty({ description: 'IPNS name of the shared item' })
  ipnsName!: string;

  @ApiProperty({ description: 'Display name of the shared item' })
  itemName!: string;

  @ApiProperty({ description: 'Hex-encoded ECIES-wrapped key for recipient' })
  encryptedKey!: string;

  @ApiProperty({ description: 'When the share was created' })
  createdAt!: Date;
}

export class ReceivedShareResponseDto {
  @ApiProperty()
  shareId!: string;

  @ApiProperty({ description: 'Sharer secp256k1 public key (0x04...)' })
  sharerPublicKey!: string;

  @ApiProperty({ enum: ['folder', 'file'] })
  itemType!: string;

  @ApiProperty()
  ipnsName!: string;

  @ApiProperty()
  itemName!: string;

  @ApiProperty({ description: 'Hex-encoded ECIES-wrapped key for recipient' })
  encryptedKey!: string;

  @ApiProperty()
  createdAt!: Date;
}

export class SentShareResponseDto {
  @ApiProperty()
  shareId!: string;

  @ApiProperty({ description: 'Recipient secp256k1 public key (0x04...)' })
  recipientPublicKey!: string;

  @ApiProperty({ enum: ['folder', 'file'] })
  itemType!: string;

  @ApiProperty()
  ipnsName!: string;

  @ApiProperty()
  itemName!: string;

  @ApiProperty()
  createdAt!: Date;
}

export class PendingRotationResponseDto {
  @ApiProperty()
  shareId!: string;

  @ApiProperty({ description: 'Recipient secp256k1 public key (0x04...)' })
  recipientPublicKey!: string;

  @ApiProperty({ enum: ['folder', 'file'] })
  itemType!: string;

  @ApiProperty()
  ipnsName!: string;

  @ApiProperty()
  itemName!: string;

  @ApiProperty()
  revokedAt!: Date;
}

export class ShareKeyResponseDto {
  @ApiProperty({ enum: ['file', 'folder'] })
  keyType!: string;

  @ApiProperty({ description: 'UUID of the file or folder' })
  itemId!: string;

  @ApiProperty({ description: 'Hex-encoded ECIES-wrapped key for recipient' })
  encryptedKey!: string;
}
