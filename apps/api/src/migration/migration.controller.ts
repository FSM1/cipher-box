import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  UseGuards,
  Request,
  ParseUUIDPipe,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RequestWithUser } from '../common/types';
import { MigrationService } from './migration.service';
import { StartMigrationDto } from './dto/start-migration.dto';
import { MigrationStatusDto } from './dto/migration-status.dto';

@ApiTags('migration')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('migration')
export class MigrationController {
  constructor(private readonly migrationService: MigrationService) {}

  @Post('start')
  @ApiOperation({ summary: 'Start a pin migration between providers' })
  @ApiResponse({ status: 201, description: 'Migration started' })
  @ApiResponse({ status: 409, description: 'Active migration already exists' })
  async startMigration(
    @Request() req: RequestWithUser,
    @Body() dto: StartMigrationDto
  ): Promise<{ migrationId: string }> {
    const migrationId = await this.migrationService.startMigration(req.user.id, dto);
    return { migrationId };
  }

  @Get('status')
  @ApiOperation({ summary: 'Get latest migration status' })
  @ApiResponse({ status: 200, type: MigrationStatusDto })
  async getStatus(@Request() req: RequestWithUser): Promise<MigrationStatusDto | null> {
    return this.migrationService.getStatus(req.user.id);
  }

  @Post(':id/pause')
  @ApiOperation({ summary: 'Pause an active migration' })
  @ApiResponse({ status: 200, description: 'Migration paused' })
  async pauseMigration(
    @Request() req: RequestWithUser,
    @Param('id', ParseUUIDPipe) id: string
  ): Promise<{ message: string }> {
    await this.migrationService.pauseMigration(req.user.id, id);
    return { message: 'Migration paused' };
  }

  @Post(':id/resume')
  @ApiOperation({ summary: 'Resume a paused migration' })
  @ApiResponse({ status: 200, description: 'Migration resumed' })
  async resumeMigration(
    @Request() req: RequestWithUser,
    @Param('id', ParseUUIDPipe) id: string
  ): Promise<{ message: string }> {
    await this.migrationService.resumeMigration(req.user.id, id);
    return { message: 'Migration resumed' };
  }

  @Post(':id/cancel')
  @ApiOperation({ summary: 'Cancel a migration' })
  @ApiResponse({ status: 200, description: 'Migration cancelled' })
  async cancelMigration(
    @Request() req: RequestWithUser,
    @Param('id', ParseUUIDPipe) id: string
  ): Promise<{ message: string }> {
    await this.migrationService.cancelMigration(req.user.id, id);
    return { message: 'Migration cancelled' };
  }
}
