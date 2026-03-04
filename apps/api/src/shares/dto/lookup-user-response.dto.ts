import { ApiProperty } from '@nestjs/swagger';

export class LookupUserResponseDto {
  @ApiProperty({ description: 'Whether a registered user was found for the given public key' })
  exists!: boolean;
}
