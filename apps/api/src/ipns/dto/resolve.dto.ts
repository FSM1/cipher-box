import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Matches, MaxLength } from 'class-validator';

export class ResolveIpnsQueryDto {
  @ApiProperty({
    description: 'IPNS name to resolve (k51... CIDv1 format)',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  @IsString()
  @IsNotEmpty()
  // [SECURITY: MEDIUM-12] IPNS name validation - accept k51 (base36) or bafzaa (base32) CIDv1 libp2p-key
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(70)
  ipnsName!: string;
}

export class ResolveIpnsResponseDto {
  @ApiProperty({
    description: 'Whether the resolution succeeded',
    example: true,
  })
  success!: boolean;

  @ApiProperty({
    description: 'CID that the IPNS name currently points to',
    example: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
  })
  cid!: string;

  @ApiProperty({
    description: 'Current sequence number of the IPNS record (bigint as string)',
    example: '1',
  })
  sequenceNumber!: string;
}
