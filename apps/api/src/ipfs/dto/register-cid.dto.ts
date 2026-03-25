import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsInt, Min, Max, IsNotEmpty, Matches } from 'class-validator';

// Max file size matches upload limit (100MB)
const MAX_FILE_SIZE = 100 * 1024 * 1024;

export class RegisterCidDto {
  @ApiProperty({ description: 'IPFS CID pinned to external provider (CIDv0 or CIDv1)' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[a-z2-7]{58,})$/, {
    message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (bafy...) string',
  })
  cid!: string;

  @ApiProperty({ description: 'Size of the pinned content in bytes' })
  @IsInt()
  @Min(1)
  @Max(MAX_FILE_SIZE)
  sizeBytes!: number;
}

export class RegisterCidResponseDto {
  @ApiProperty({ description: 'Whether the CID was recorded' })
  recorded!: boolean;
}
