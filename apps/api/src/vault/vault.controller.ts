import {
  Controller,
  Post,
  Get,
  Patch,
  Body,
  UseGuards,
  Request,
  NotFoundException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { VaultService } from './vault.service';
import { InitVaultDto, VaultResponseDto } from './dto/init-vault.dto';
import { VaultExportDto } from './dto/vault-export.dto';
import { QuotaResponseDto } from './dto/quota.dto';
import { VaultConfigResponseDto } from './dto/vault-config.dto';
import { SetByoStatusDto } from './dto/byo-status.dto';
import { RequestWithUser } from '../common/types';

@ApiTags('Vault')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('vault')
export class VaultController {
  constructor(private readonly vaultService: VaultService) {}

  @Post('init')
  @ApiOperation({
    summary: 'Initialize user vault',
    description:
      'Create a new vault with encrypted keys on first sign-in. Returns 409 Conflict if vault already exists.',
  })
  @ApiResponse({
    status: 201,
    description: 'Vault initialized successfully',
    type: VaultResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 409,
    description: 'Conflict - Vault already exists for this user',
  })
  async initializeVault(
    @Request() req: RequestWithUser,
    @Body() dto: InitVaultDto
  ): Promise<VaultResponseDto> {
    return this.vaultService.initializeVault(req.user.id, dto);
  }

  @Get('config')
  @ApiOperation({
    summary: 'Get vault configuration',
    description:
      'Returns application configuration including recycle bin retention period. The retention period is configurable via the RECYCLE_BIN_RETENTION_DAYS environment variable (default: 30).',
  })
  @ApiResponse({
    status: 200,
    description: 'Vault configuration',
    type: VaultConfigResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  getConfig(): VaultConfigResponseDto {
    return this.vaultService.getConfig();
  }

  @Get('export')
  @ApiOperation({
    summary: 'Export vault for independent recovery',
    description:
      'Returns the minimal vault data needed for independent recovery: root IPNS name, encrypted root keys, and derivation hints.',
  })
  @ApiResponse({
    status: 200,
    description: 'Vault export data',
    type: VaultExportDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Vault does not exist',
  })
  async exportVault(@Request() req: RequestWithUser): Promise<VaultExportDto> {
    return this.vaultService.getExportData(req.user.id);
  }

  @Get()
  @ApiOperation({
    summary: 'Get user vault',
    description: 'Retrieve the vault for the authenticated user.',
  })
  @ApiResponse({
    status: 200,
    description: 'Vault retrieved successfully',
    type: VaultResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Vault does not exist',
  })
  async getVault(@Request() req: RequestWithUser): Promise<VaultResponseDto> {
    const vault = await this.vaultService.findVault(req.user.id);
    if (!vault) {
      throw new NotFoundException('Vault not found');
    }
    return vault;
  }

  @Get('quota')
  @ApiOperation({
    summary: 'Get storage quota',
    description: 'Get current storage usage and limits. Limit is 500 MiB (524,288,000 bytes).',
  })
  @ApiResponse({
    status: 200,
    description: 'Quota retrieved successfully',
    type: QuotaResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  async getQuota(@Request() req: RequestWithUser): Promise<QuotaResponseDto> {
    return this.vaultService.getQuota(req.user.id);
  }

  @Patch('byo-status')
  @ApiOperation({
    summary: 'Set BYO IPFS mode',
    description:
      'Toggle BYO (Bring Your Own) IPFS mode for the authenticated user. ' +
      'When enabled, quota tracking becomes advisory only.',
  })
  @ApiResponse({ status: 200, description: 'BYO status updated' })
  @ApiResponse({ status: 401, description: 'Unauthorized - JWT token required' })
  @ApiResponse({ status: 404, description: 'Not Found - Vault does not exist' })
  async setByoStatus(
    @Request() req: RequestWithUser,
    @Body() dto: SetByoStatusDto
  ): Promise<{ success: boolean }> {
    const vault = await this.vaultService.findVault(req.user.id);
    if (!vault) {
      throw new NotFoundException('Vault not found');
    }
    await this.vaultService.setByoStatus(req.user.id, dto.isByo);
    return { success: true };
  }
}
