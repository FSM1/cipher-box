import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsInt, Min, Max, IsNotEmpty, Matches, MaxLength } from 'class-validator';
import { CID_REGEX } from './cid.constants';

// Max file size matches upload limit (100MB)
const MAX_FILE_SIZE = 100 * 1024 * 1024;

export class RegisterCidDto {
  @ApiProperty({
    description: 'IPFS CID pinned to external provider (CIDv0 or CIDv1)',
    pattern: CID_REGEX.source,
    maxLength: 255,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  @Matches(CID_REGEX, { message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (b...) string' })
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
