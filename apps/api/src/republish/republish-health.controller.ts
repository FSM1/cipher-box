import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RepublishService } from './republish.service';

@ApiTags('Admin')
@ApiBearerAuth()
@Controller('admin')
export class RepublishHealthController {
  constructor(private readonly republishService: RepublishService) {}

  @Get('republish-health')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: 'Get IPNS republish health stats',
    description:
      'Returns aggregate counts of pending, failed, and stale republish jobs, plus TEE connectivity status. Requires JWT authentication.',
  })
  @ApiResponse({
    status: 200,
    description: 'Republish health statistics',
    schema: {
      type: 'object',
      properties: {
        pending: {
          type: 'number',
          description: 'Active entries awaiting next republish cycle',
        },
        failed: {
          type: 'number',
          description: 'Entries currently in retry with exponential backoff',
        },
        stale: {
          type: 'number',
          description: 'Entries that exceeded max retries and need TEE recovery',
        },
        lastRunAt: {
          type: 'string',
          format: 'date-time',
          nullable: true,
          description: 'Timestamp of most recent successful republish',
        },
        currentEpoch: {
          type: 'number',
          nullable: true,
          description: 'Current TEE key epoch number',
        },
        teeHealthy: {
          type: 'boolean',
          description: 'Whether the TEE worker is reachable and healthy',
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Not authenticated' })
  async getHealth() {
    const stats = await this.republishService.getHealthStats();
    return {
      pending: stats.pending,
      failed: stats.failed,
      stale: stats.stale,
      lastRunAt: stats.lastRunAt,
      currentEpoch: stats.currentEpoch,
      teeHealthy: stats.teeHealthy,
    };
  }
}
