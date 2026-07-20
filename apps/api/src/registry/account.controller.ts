import { Body, Controller, Get, Patch, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthenticatedRequest, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { ByoResponseDto, QuotaResponseDto, SetByoDto } from './dto/registry.dto';
import { RegistryService } from './services/registry.service';

/**
 * Account-scoped registry surface (blueprint/api.md): the per-account quota
 * derived from the caller's pin rows, and the BYO-IPFS toggle that flips those
 * rows between authoritative (hosted) and advisory. Both are authenticated and
 * act on the caller's OWN account.
 */
@ApiTags('Account')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('account')
export class AccountController {
  constructor(private readonly registryService: RegistryService) {}

  @Get('quota')
  @Throttle(THROTTLE_SURFACES.account)
  @ApiOperation({
    summary:
      'The caller per-account quota: usedBytes (sum over pin rows), limitBytes (override or env default), advisory (BYO)',
  })
  @ApiOkResponse({ type: QuotaResponseDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  quota(@Req() request: AuthenticatedRequest): Promise<QuotaResponseDto> {
    return this.registryService.quota(request.user.userId);
  }

  @Patch('byo')
  @Throttle(THROTTLE_SURFACES.account)
  @ApiOperation({ summary: 'Toggle the caller BYO-IPFS flag; advisory pin rows follow it' })
  @ApiOkResponse({ type: ByoResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed body' })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  setByo(@Body() body: SetByoDto, @Req() request: AuthenticatedRequest): Promise<ByoResponseDto> {
    return this.registryService.setByo(request.user.userId, body.byo);
  }
}
