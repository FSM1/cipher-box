import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiProperty, ApiTags } from '@nestjs/swagger';
import { SkipThrottle } from '@nestjs/throttler';

export class HealthResponseDto {
  @ApiProperty({ example: 'ok' })
  status!: string;
}

@ApiTags('Ops')
@Controller('health')
export class HealthController {
  @Get()
  @SkipThrottle()
  @ApiOperation({ summary: 'Liveness check' })
  @ApiOkResponse({ type: HealthResponseDto })
  getHealth(): HealthResponseDto {
    return { status: 'ok' };
  }
}
