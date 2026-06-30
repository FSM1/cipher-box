import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator';

export class TombstoneIpnsDto {
  @ApiProperty({
    description: 'IPNS name to tombstone (k51... CIDv1 format)',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  @IsString()
  @IsNotEmpty()
  // [SECURITY: MEDIUM-12] IPNS name validation — same pattern as publish endpoint
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(76)
  ipnsName!: string;
}
