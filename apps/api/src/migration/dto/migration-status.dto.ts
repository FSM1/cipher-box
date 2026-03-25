import { ApiProperty } from '@nestjs/swagger';

export class MigrationStatusDto {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  status!: string;

  @ApiProperty()
  totalCids!: number;

  @ApiProperty()
  migratedCids!: number;

  @ApiProperty()
  failedCids!: number;

  @ApiProperty()
  createdAt!: string;

  @ApiProperty({ nullable: true })
  completedAt!: string | null;
}
