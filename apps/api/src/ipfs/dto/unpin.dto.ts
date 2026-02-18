import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class UnpinDto {
  @ApiProperty({
    description: 'The IPFS CID of the file to unpin',
    example: 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
  })
  @IsString()
  @IsNotEmpty()
  cid!: string;
}

export class UnpinResponseDto {
  @ApiProperty({
    description: 'Whether the unpin operation was successful',
    example: true,
  })
  success!: boolean;
}
