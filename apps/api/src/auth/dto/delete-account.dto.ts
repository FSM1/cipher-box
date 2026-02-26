import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class DeleteAccountDto {
  @ApiProperty({
    description: 'Must be the string "DELETE" to confirm account deletion',
    example: 'DELETE',
  })
  @IsString()
  @IsNotEmpty()
  confirmation!: string;
}

export class DeleteAccountResponseDto {
  @ApiProperty({ description: 'Whether the account was successfully deleted' })
  success!: boolean;
}
