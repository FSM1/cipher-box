import { Controller, Get, Header } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { SkipThrottle } from '@nestjs/throttler';
import { MetricsService } from './metrics.service';

@ApiTags('Ops')
@Controller('metrics')
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  @Get()
  @SkipThrottle()
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  @ApiOperation({ summary: 'Prometheus metrics in text exposition format' })
  @ApiOkResponse({ type: String, description: 'Prometheus text exposition format' })
  getMetrics(): Promise<string> {
    return this.metricsService.metricsText();
  }
}
