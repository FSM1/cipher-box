import { ApiProperty } from '@nestjs/swagger';

export class AddResponseDto {
  @ApiProperty({
    description: 'The IPFS CID of the pinned file',
    example: 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
  })
  cid!: string;

  @ApiProperty({
    description: 'The size of the pinned file in bytes',
    example: 1024,
  })
  size!: number;
}
