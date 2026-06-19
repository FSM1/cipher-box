import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, MaxLength, Matches } from 'class-validator';

// IN-02: CID format regex covers CIDv0 (Qm... base58, 46 chars) and
// CIDv1 (b... base32, 59+ chars). MaxLength(255) bounds the input to
// prevent oversized-string DoS at the route boundary (T-50-12).
const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;

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
