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
 * Deliberately outside `JwtAuthGuard` — the credential is opaque, not a JWT,
 * and the whole point is that the gateway tier learns nothing about the account
 * behind it (blueprint/api.md, Egress).
 */
@ApiTags('Auth')
@Controller('auth/gateway')
export class GatewayController {
  constructor(private readonly gatewayTokenService: GatewayTokenService) {}

  /**
   * Unthrottled: every member's reads arrive from the one gateway front, so a
   * per-IP bucket would count them all together and stall the read path at the
   * first busy member. The shape gate and the in-process cache are what keep a
   * spray of invalid tokens off the database.
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
