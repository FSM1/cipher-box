import {
  BadRequestException,
  Body,
  Controller,
  ParseArrayPipe,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthenticatedRequest, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import {
  MAX_BATCH,
  REGISTER_ARRAY_OPTIONS,
  RegisterEntryDto,
  RegisterResponseDto,
  RETIRE_ARRAY_OPTIONS,
  RetireResponseDto,
} from './dto/registry.dto';
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
  @ApiCreatedResponse({ type: RegisterResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed batch (invalid entry, name, or CID)' })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Registry rate limit exceeded' })
  register(
    @Body(new ParseArrayPipe(REGISTER_ARRAY_OPTIONS)) entries: RegisterEntryDto[],
    @Req() request: AuthenticatedRequest
  ): Promise<RegisterResponseDto> {
    if (entries.length > MAX_BATCH) {
      throw new BadRequestException(`Batch exceeds ${MAX_BATCH} entries`);
    }
    return this.registryService.register(request.user.userId, entries);
  }

  @Post('retire')
  @Throttle(THROTTLE_SURFACES.registry)
  @ApiOperation({
    summary:
      'Batch retire [ipnsName | cid] for the caller account; union liveness, refcounted physical unpin at global zero',
  })
  @ApiCreatedResponse({ type: RetireResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed batch' })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Registry rate limit exceeded' })
  retire(
    @Body(new ParseArrayPipe(RETIRE_ARRAY_OPTIONS)) targets: string[],
    @Req() request: AuthenticatedRequest
  ): Promise<RetireResponseDto> {
    if (targets.length > MAX_BATCH) {
      throw new BadRequestException(`Batch exceeds ${MAX_BATCH} targets`);
    }
    return this.registryService.retire(request.user.userId, targets);
  }
}
