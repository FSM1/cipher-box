import { Controller, Get, Headers, HttpCode, UnauthorizedException } from '@nestjs/common';
import {
  ApiNoContentResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { MetricsService } from '../ops/metrics.service';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { AcceleratorTokenService } from './services/accelerator-token.service';

const BEARER_PREFIX = 'Bearer ';

/**
 * The read accelerator's verify leg: the gateway front asks whether the
 * presented pseudonym still names a live session, and gets a bare yes or no.
 *
 * Deliberately outside `JwtAuthGuard` — the credential is opaque, not a JWT
 * (CONTEXT.md, Accelerator token). What the front must do with the answer is
 * blueprint/api.md, Egress.
 */
@ApiTags('Auth')
@Controller('auth/gateway')
export class GatewayController {
  constructor(
    private readonly acceleratorTokenService: AcceleratorTokenService,
    private readonly metricsService: MetricsService
  ) {}

  @Get('verify')
  @HttpCode(204)
  @Throttle(THROTTLE_SURFACES.gatewayVerify)
  @ApiOperation({
    summary: 'Verify a read accelerator token for the gateway front (forward_auth)',
  })
  @ApiNoContentResponse({ description: 'The token names a live session' })
  @ApiUnauthorizedResponse({ description: 'Missing, malformed, expired, or revoked token' })
  async verify(@Headers('authorization') authorization?: string): Promise<void> {
    if (!authorization?.startsWith(BEARER_PREFIX)) {
      this.metricsService.observeGatewayVerify('refused');
      throw new UnauthorizedException('Missing accelerator token');
    }
    const accepted = await this.acceleratorTokenService.verify(
      authorization.slice(BEARER_PREFIX.length)
    );
    this.metricsService.observeGatewayVerify(accepted ? 'accepted' : 'refused');
    if (!accepted) {
      throw new UnauthorizedException('Invalid accelerator token');
    }
  }
}
