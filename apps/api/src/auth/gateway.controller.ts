import { Controller, Get, Headers, HttpCode, UnauthorizedException } from '@nestjs/common';
import {
  ApiNoContentResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { SkipThrottle } from '@nestjs/throttler';
import { GatewayTokenService } from './services/gateway-token.service';

const BEARER_PREFIX = 'Bearer ';

/**
 * The read accelerator's verify leg: the gateway front asks whether the
 * presented pseudonym still names a live session, and gets a bare yes or no.
 *
 * Deliberately outside `JwtAuthGuard` — the credential is opaque, not a JWT
 * (CONTEXT.md, Accelerator token).
 */
@ApiTags('Auth')
@Controller('auth/gateway')
export class GatewayController {
  constructor(private readonly gatewayTokenService: GatewayTokenService) {}

  /**
   * Unthrottled here: every member's reads arrive from the one gateway front,
   * so the per-IP tracker would count them all into one bucket and stall the
   * read path at the first busy member. Bounding this surface belongs at that
   * front, which is not built yet; until it is, what keeps a spray of invented
   * tokens off the database is the shape gate plus the refusal cache.
   */
  @Get('verify')
  @HttpCode(204)
  @SkipThrottle()
  @ApiOperation({
    summary: 'Verify a read accelerator token for the gateway front (forward_auth)',
  })
  @ApiNoContentResponse({ description: 'The token names a live session' })
  @ApiUnauthorizedResponse({ description: 'Missing, malformed, expired, or revoked token' })
  async verify(@Headers('authorization') authorization?: string): Promise<void> {
    if (!authorization?.startsWith(BEARER_PREFIX)) {
      throw new UnauthorizedException('Missing accelerator token');
    }
    const accepted = await this.gatewayTokenService.verify(
      authorization.slice(BEARER_PREFIX.length)
    );
    if (!accepted) {
      throw new UnauthorizedException('Invalid accelerator token');
    }
  }
}
