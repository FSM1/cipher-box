import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsOptional, IsNumber, IsBase64, Matches } from 'class-validator';

export class PublishIpnsDto {
  @ApiProperty({
    description: 'IPNS name (k51... CIDv1 format)',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^k51/, { message: 'ipnsName must start with k51 (CIDv1 libp2p-key)' })
  ipnsName!: string;

  @ApiProperty({
    description: 'Base64-encoded marshaled IPNS record',
    example: 'CiQBqKAFp...',
  })
  @IsString()
  @IsNotEmpty()
  @IsBase64()
  record!: string;

  @ApiProperty({
    description: 'CID of the encrypted metadata this record points to',
    example: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
  })
  @IsString()
  @IsNotEmpty()
  metadataCid!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES-wrapped Ed25519 private key for TEE republishing (required on first publish)',
    required: false,
    example: '04abcd1234...',
  })
  @IsString()
  @IsOptional()
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
