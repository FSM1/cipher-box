import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthenticatedRequest, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { RegisterEntryDto, RegisterResponseDto, RetireResponseDto } from './dto/registry.dto';
import { registerBodyPipes, retireBodyPipes } from './registry.pipes';
import { RegistryService } from './services/registry.service';

/**
 * The pin/name registry surface (blueprint/api.md, Pin/name registry): the one
 * surface every publish flow traverses, feeding both quota and the republisher
 * inventory. Both routes are authenticated and act on the caller's OWN
 * account; both take a top-level JSON array (single-item batches for ordinary
 * writes, bulk for name waves and sweeps) and are idempotent.
 */
@ApiTags('Registry')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('registry')
export class RegistryController {
  constructor(private readonly registryService: RegistryService) {}

  @Post('register')
  @Throttle(THROTTLE_SURFACES.registry)
  @ApiOperation({
    summary:
      'Batch register [{ipnsName, headCid?, contentCids[]}] under the caller account; register-first, idempotent upserts',
  })
  @ApiBody({ type: RegisterEntryDto, isArray: true })
  @ApiCreatedResponse({ type: RegisterResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed batch (invalid entry, name, or CID)' })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Registry rate limit exceeded' })
  register(
    @Body(...registerBodyPipes) entries: RegisterEntryDto[],
    @Req() request: AuthenticatedRequest
  ): Promise<RegisterResponseDto> {
    return this.registryService.register(request.user.userId, entries);
  }

  @Post('retire')
  @Throttle(THROTTLE_SURFACES.registry)
  @ApiOperation({
    summary:
      'Batch retire [ipnsName | cid] for the caller account; union liveness, refcounted physical unpin at global zero',
  })
  @ApiBody({ type: String, isArray: true })
  @ApiCreatedResponse({ type: RetireResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed batch' })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Registry rate limit exceeded' })
  retire(
    @Body(...retireBodyPipes) targets: string[],
    @Req() request: AuthenticatedRequest
  ): Promise<RetireResponseDto> {
    return this.registryService.retire(request.user.userId, targets);
  }
}
