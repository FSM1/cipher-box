import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class StartMigrationDto {
  @ApiProperty({
    description: 'Source provider config encrypted with TEE public key (ECIES)',
  })
  @IsString()
  @IsNotEmpty()
  sourceConfigEncrypted!: string;

  @ApiProperty({
    description: 'Destination provider config encrypted with TEE public key (ECIES)',
  })
  @IsString()
  @IsNotEmpty()
  destConfigEncrypted!: string;
}
