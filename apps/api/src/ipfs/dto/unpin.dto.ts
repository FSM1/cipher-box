import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, MaxLength, Matches } from 'class-validator';
import { CID_REGEX } from './cid.constants';

export class UnpinDto {
  @ApiProperty({
    description:
      'The IPFS CID of the file to unpin. Must be a valid CIDv0 (Qm... base58) or CIDv1 (b... base32). Max 255 characters.',
    example: 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
    pattern: '^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$',
    maxLength: 255,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  @Matches(CID_REGEX, { message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (b...) string' })
  cid!: string;
}

export class UnpinResponseDto {
  @ApiProperty({
    description: 'Whether the unpin operation was successful',
    example: true,
  })
  success!: boolean;
}
