import { ApiProperty } from '@nestjs/swagger';
import { IsInt, Min, Max, IsOptional } from 'class-validator';
import { Type } from 'class-transformer';
import { ReceivedShareResponseDto, SentShareResponseDto } from './share-response.dto';

export class PaginationQueryDto {
  @ApiProperty({ description: 'Maximum number of items to return', default: 50, required: false })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit: number = 50;

  @ApiProperty({ description: 'Number of items to skip', default: 0, required: false })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  offset: number = 0;
}

export class PaginatedReceivedSharesDto {
  @ApiProperty({ type: [ReceivedShareResponseDto] })
  shares!: ReceivedShareResponseDto[];

  @ApiProperty({ description: 'Total number of matching shares' })
  total!: number;
}

export class PaginatedSentSharesDto {
  @ApiProperty({ type: [SentShareResponseDto] })
  shares!: SentShareResponseDto[];

  @ApiProperty({ description: 'Total number of matching shares' })
  total!: number;
}
