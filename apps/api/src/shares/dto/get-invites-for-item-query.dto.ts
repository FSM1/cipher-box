import { ApiProperty } from '@nestjs/swagger';
import { IsString, Matches, MaxLength } from 'class-validator';

export class GetInvitesForItemQueryDto {
  @ApiProperty({
    description: 'IPNS name (k51...) of the root shared node',
  })
  @IsString()
  // Canonical CIDv1 libp2p-key validator (matches CreateInviteDto / ipns resolve/tombstone DTOs):
  // k51qzi5uqu5... (base36 PeerID-style) or bafzaa... (base32 IPNS key CID).
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    message: 'shareRootIpnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(255)
  shareRootIpnsName!: string;
}
