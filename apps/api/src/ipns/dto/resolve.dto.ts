import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Matches, MaxLength } from 'class-validator';

export class ResolveIpnsQueryDto {
  @ApiProperty({
    description:
      'IPNS name to resolve. Supports CIDv1 IPNS names starting with "k51..." (PeerID-style) or "bafzaa..." (IPNS key CID).',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  @IsString()
  @IsNotEmpty()
  // [SECURITY: MEDIUM-12] IPNS name validation - accept k51 (base36) or bafzaa (base32) CIDv1 libp2p-key
  // k51qzi5uqu5 (11 chars) + 40-60 = 51-71 chars; bafzaa (6 chars) + 50-70 = 56-76 chars
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(76)
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
