import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsUUID,
  IsNumberString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

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
    description:
      'Hex-encoded ECIES descriptor ref for read access (wrapped root readKey + metadata). ' +
      'Server never sees plaintext (zero-knowledge).',
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'readDescriptorRef must be an even-length hex string',
  })
  @MinLength(64)
  @MaxLength(4096)
  readDescriptorRef!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES descriptor ref for write access. ' +
      'Presence signals a write grant (D-09). Omit for read-only shares.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'writeDescriptorRef must be an even-length hex string',
  })
  @MinLength(64)
  @MaxLength(4096)
  @IsOptional()
  writeDescriptorRef?: string;

  @ApiProperty({
    description: 'UUID of the root shared node (folder or file)',
  })
  @IsUUID()
  rootNodeId!: string;

  @ApiProperty({
    description: 'IPNS name (k51...) of the root shared node',
  })
  @IsString()
  // Canonical CIDv1 libp2p-key validator (matches ipns resolve/tombstone DTOs):
  // k51qzi5uqu5... (base36 PeerID-style) or bafzaa... (base32 IPNS key CID).
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'rootIpnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(255)
  rootIpnsName!: string;

  @ApiProperty({
    description: 'Generation of the root node at share time (numeric string)',
    required: false,
    default: '0',
  })
  @IsNumberString()
  @IsOptional()
  rootGeneration?: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES ciphertext of the display name wrapped for recipient. ' +
      'Optional: omit if recipient can derive the name from their filesystem.',
    required: false,
  })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, {
    message: 'itemNameEncrypted must be an even-length hex string',
  })
  @MaxLength(2500)
  @IsOptional()
  itemNameEncrypted?: string;
}
