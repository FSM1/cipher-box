import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsNumber,
  IsBase64,
  IsArray,
  IsIn,
  ArrayMaxSize,
  ArrayMinSize,
  ValidateNested,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Type } from 'class-transformer';

export class PublishIpnsDto {
  @ApiProperty({
    description: 'IPNS name (k51... CIDv1 format)',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  @IsString()
  @IsNotEmpty()
  // [SECURITY: MEDIUM-12] IPNS name validation - accept k51 (base36) or bafzaa (base32) CIDv1 libp2p-key
  // Both formats are accepted for forward compatibility and external tool support.
  // Client code generates base36 (k51...) format, but we accept base32 (bafzaa...) for interoperability.
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(70)
  ipnsName!: string;

  @ApiProperty({
    description: 'Base64-encoded marshaled IPNS record',
    example: 'CiQBqKAFp...',
  })
  @IsString()
  @IsNotEmpty()
  @IsBase64()
  @MaxLength(10000) // IPNS records should be small
  record!: string;

  @ApiProperty({
    description: 'CID of the encrypted metadata this record points to',
    example: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
  })
  @IsString()
  @IsNotEmpty()
  // [SECURITY: MEDIUM-10] Validate CID format - must start with bafy/bafk (CIDv1) or Qm (CIDv0)
  @Matches(/^(bafy|bafk|Qm)[a-zA-Z0-9]+$/, {
    message: 'metadataCid must be a valid CID (bafy..., bafk..., or Qm...)',
  })
  @MaxLength(100)
  metadataCid!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES-wrapped Ed25519 private key for TEE republishing (required on first publish)',
    required: false,
    example: '04abcd1234...',
  })
  @IsString()
  @IsOptional()
  // [SECURITY: MEDIUM-09] Validate hex format and reasonable length for ECIES ciphertext
  @Matches(/^[0-9a-fA-F]+$/, {
    message: 'encryptedIpnsPrivateKey must be hex-encoded',
  })
  @MinLength(100, {
    message: 'encryptedIpnsPrivateKey too short for ECIES ciphertext',
  })
  @MaxLength(1000, {
    message: 'encryptedIpnsPrivateKey too long',
  })
  encryptedIpnsPrivateKey?: string;

  @ApiProperty({
    description: 'TEE key epoch (required with encryptedIpnsPrivateKey)',
    required: false,
    example: 1,
  })
  @IsNumber()
  @IsOptional()
  keyEpoch?: number;
}

export class PublishIpnsResponseDto {
  @ApiProperty({
    description: 'Whether the publish operation succeeded',
    example: true,
  })
  success!: boolean;

  @ApiProperty({
    description: 'IPNS name that was published',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  ipnsName!: string;

  @ApiProperty({
    description: 'Current sequence number (bigint as string)',
    example: '1',
  })
  sequenceNumber!: string;
}

/**
 * Single entry within a batch publish request.
 * Same fields as PublishIpnsDto plus optional recordType.
 */
export class PublishIpnsEntryDto {
  @ApiProperty({
    description: 'IPNS name (k51... CIDv1 format)',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(70)
  ipnsName!: string;

  @ApiProperty({
    description: 'Base64-encoded marshaled IPNS record',
    example: 'CiQBqKAFp...',
  })
  @IsString()
  @IsNotEmpty()
  @IsBase64()
  @MaxLength(10000)
  record!: string;

  @ApiProperty({
    description: 'CID of the encrypted metadata this record points to',
    example: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^(bafy|bafk|Qm)[a-zA-Z0-9]+$/, {
    message: 'metadataCid must be a valid CID (bafy..., bafk..., or Qm...)',
  })
  @MaxLength(100)
  metadataCid!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES-wrapped Ed25519 private key for TEE republishing',
    required: false,
    example: '04abcd1234...',
  })
  @IsString()
  @IsOptional()
  @Matches(/^[0-9a-fA-F]+$/, {
    message: 'encryptedIpnsPrivateKey must be hex-encoded',
  })
  @MinLength(100, {
    message: 'encryptedIpnsPrivateKey too short for ECIES ciphertext',
  })
  @MaxLength(1000, {
    message: 'encryptedIpnsPrivateKey too long',
  })
  encryptedIpnsPrivateKey?: string;

  @ApiProperty({
    description: 'TEE key epoch (required with encryptedIpnsPrivateKey)',
    required: false,
    example: 1,
  })
  @IsNumber()
  @IsOptional()
  keyEpoch?: number;

  @ApiProperty({
    description: "Record type: 'folder' for folder metadata, 'file' for per-file metadata",
    required: false,
    enum: ['folder', 'file'],
    default: 'folder',
    example: 'file',
  })
  @IsString()
  @IsOptional()
  @IsIn(['folder', 'file'])
  recordType?: 'folder' | 'file';
}

/**
 * Batch publish request: up to 200 IPNS records in a single API call.
 */
export class BatchPublishIpnsDto {
  @ApiProperty({
    description: 'Array of IPNS records to publish (max 200)',
    type: [PublishIpnsEntryDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PublishIpnsEntryDto)
  @ArrayMinSize(1)
  @ArrayMaxSize(200)
  records!: PublishIpnsEntryDto[];
}

/**
 * Batch publish response with per-record results and summary counts.
 */
export class BatchPublishIpnsResponseDto {
  @ApiProperty({
    description: 'Per-record publish results',
    type: [PublishIpnsResponseDto],
  })
  results!: PublishIpnsResponseDto[];

  @ApiProperty({
    description: 'Number of records that succeeded',
    example: 5,
  })
  totalSucceeded!: number;

  @ApiProperty({
    description: 'Number of records that failed',
    example: 0,
  })
  totalFailed!: number;
}
