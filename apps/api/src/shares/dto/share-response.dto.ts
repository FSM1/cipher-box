import { ApiProperty } from '@nestjs/swagger';

export class CreateShareResponseDto {
  @ApiProperty({ description: 'UUID of the created share' })
  shareId!: string;

  @ApiProperty({ description: 'Recipient secp256k1 public key (0x04...)' })
  recipientPublicKey!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES encrypted key for read access',
  })
  encryptedReadKey!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES encrypted key for write access, or null for read-only shares',
    type: String,
    nullable: true,
  })
  encryptedWriteKey!: string | null;

  @ApiProperty({ description: 'UUID of the root shared node' })
  rootNodeId!: string;

  @ApiProperty({ description: 'IPNS name (k51...) of the root shared node' })
  shareRootIpnsName!: string;

  @ApiProperty({ description: 'Generation of the root node at share creation (numeric string)' })
  rootGeneration!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the display name, or null if not provided',
    type: String,
    nullable: true,
  })
  itemNameEncrypted!: string | null;

  @ApiProperty({ description: 'When the share was created' })
  createdAt!: Date;
}

export class ReceivedShareResponseDto {
  @ApiProperty()
  shareId!: string;

  @ApiProperty({ description: 'Sharer secp256k1 public key (0x04...)' })
  sharerPublicKey!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES encrypted key for read access',
  })
  encryptedReadKey!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES encrypted key for write access, or null for read-only shares',
    type: String,
    nullable: true,
  })
  encryptedWriteKey!: string | null;

  @ApiProperty({ description: 'UUID of the root shared node' })
  rootNodeId!: string;

  @ApiProperty({ description: 'IPNS name (k51...) of the root shared node' })
  shareRootIpnsName!: string;

  @ApiProperty({ description: 'Generation of the root node at share creation (numeric string)' })
  rootGeneration!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the display name, or null if not provided',
    type: String,
    nullable: true,
  })
  itemNameEncrypted!: string | null;

  @ApiProperty()
  createdAt!: Date;
}

export class SentShareResponseDto {
  @ApiProperty()
  shareId!: string;

  @ApiProperty({ description: 'Recipient secp256k1 public key (0x04...)' })
  recipientPublicKey!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES encrypted key for read access',
  })
  encryptedReadKey!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES encrypted key for write access, or null for read-only shares',
    type: String,
    nullable: true,
  })
  encryptedWriteKey!: string | null;

  @ApiProperty({ description: 'UUID of the root shared node' })
  rootNodeId!: string;

  @ApiProperty({ description: 'IPNS name (k51...) of the root shared node' })
  shareRootIpnsName!: string;

  @ApiProperty({ description: 'Generation of the root node at share creation (numeric string)' })
  rootGeneration!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the display name, or null if not provided',
    type: String,
    nullable: true,
  })
  itemNameEncrypted!: string | null;

  @ApiProperty()
  createdAt!: Date;
}

export class RevokeForItemsResponseDto {
  @ApiProperty({
    description: 'Number of Share rows hard-deleted',
  })
  revokedShares!: number;

  @ApiProperty({
    description: "Number of active ShareInvite rows marked 'revoked'",
  })
  revokedInvites!: number;
}
