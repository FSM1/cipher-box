import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsString, ArrayMaxSize, ArrayMinSize, Matches, MaxLength } from 'class-validator';

export class BatchUnenrollIpnsDto {
  @ApiProperty({
    description: 'Array of IPNS names to unenroll from TEE republishing (max 200)',
    type: [String],
    example: ['k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz'],
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(200)
  @IsString({ each: true })
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    each: true,
    message: 'Each ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  @MaxLength(76, { each: true })
  ipnsNames!: string[];
}

export class BatchUnenrollIpnsResponseDto {
  @ApiProperty({ description: 'Number of IPNS names successfully unenrolled', example: 5 })
  totalUnenrolled!: number;

  @ApiProperty({ description: 'Total IPNS names in the request', example: 5 })
  totalRequested!: number;
}
