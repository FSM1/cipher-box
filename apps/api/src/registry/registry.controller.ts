import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiExtraModels,
  ApiOperation,
  ApiResponse,
  ApiTags,
  getSchemaPath,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthenticatedRequest, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import {
  MAX_BATCH,
  RegisterEntryDto,
  RegisterResponseDto,
  RetireEntryDto,
  RetireResponseDto,
} from './dto/registry.dto';
import { BatchRefusedDto, REGISTRY_BATCH_REFUSED } from './registry-error-codes';
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
@ApiExtraModels(RegisterEntryDto, RetireEntryDto)
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
  @ApiBody({
    schema: {
      type: 'array',
      maxItems: MAX_BATCH,
      items: { $ref: getSchemaPath(RegisterEntryDto) },
    },
  })
  @ApiCreatedResponse({ type: RegisterResponseDto })
  @ApiResponse({
    status: 400,
    type: BatchRefusedDto,
    description: `Malformed or over-cap batch; the body carries code ${REGISTRY_BATCH_REFUSED}`,
  })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Registry rate limit exceeded' })
  @ApiResponse({ status: 503, description: 'Token serialization contended; retry shortly' })
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
      'Batch retire [{ipnsName?, targets[]}] for the caller account; a scoped entry drops only that record reference, union liveness, refcounted physical unpin at global zero',
  })
  @ApiBody({
    schema: {
      type: 'array',
      maxItems: MAX_BATCH,
      items: { $ref: getSchemaPath(RetireEntryDto) },
    },
  })
  @ApiCreatedResponse({ type: RetireResponseDto })
  @ApiResponse({
    status: 400,
    type: BatchRefusedDto,
    description: `Malformed or over-cap batch; the body carries code ${REGISTRY_BATCH_REFUSED}`,
  })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Registry rate limit exceeded' })
  @ApiResponse({ status: 503, description: 'Token serialization contended; retry shortly' })
  retire(
    @Body(...retireBodyPipes) entries: RetireEntryDto[],
    @Req() request: AuthenticatedRequest
  ): Promise<RetireResponseDto> {
    return this.registryService.retire(request.user.userId, entries);
  }
}
