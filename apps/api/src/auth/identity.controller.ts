import { Body, Controller, Get, Header, HttpCode, Post, UseInterceptors } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { AuthMetricsInterceptor } from './auth-metrics.interceptor';
import { SiweLoginRequestDto } from './dto/auth.dto';
import {
  EmailCodeRequestDto,
  EmailCodeSentResponseDto,
  EmailCodeVerifyRequestDto,
  GoogleIdentityRequestDto,
  IdentityTokenResponseDto,
  JwksResponseDto,
} from './dto/identity.dto';
import { IdentityExchangeService, IdentityGrant } from './services/identity-exchange.service';
import { IdentityTokenService } from './services/identity-token.service';

/**
 * The identity exchange (ADR 0008 D1/D2): a verified provider credential in,
 * a CipherBox identity token out.
 *
 * Unauthenticated by construction — it runs before a login secret exists, so
 * the caller is the host application over plain HTTP, never the engine.
 */
@ApiTags('Identity')
@Controller('auth')
@UseInterceptors(AuthMetricsInterceptor)
export class IdentityController {
  constructor(
    private readonly exchange: IdentityExchangeService,
    private readonly tokens: IdentityTokenService
  ) {}

  @Get('.well-known/jwks.json')
  @Header('Cache-Control', 'public, max-age=3600')
  @ApiOperation({ summary: 'Verification keys for CipherBox-issued identity tokens' })
  @ApiOkResponse({ type: JwksResponseDto })
  jwks(): JwksResponseDto {
    return this.tokens.jwks();
  }

  @Post('identity/google')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({ summary: 'Exchange a Google ID token for a CipherBox identity token' })
  @ApiOkResponse({ type: IdentityTokenResponseDto })
  async google(@Body() body: GoogleIdentityRequestDto): Promise<IdentityTokenResponseDto> {
    return present(await this.exchange.fromGoogleToken(body.idToken));
  }

  @Post('identity/email/send-code')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({ summary: 'Send a CipherBox-issued verification code to an email address' })
  @ApiOkResponse({ type: EmailCodeSentResponseDto })
  async sendEmailCode(@Body() body: EmailCodeRequestDto): Promise<EmailCodeSentResponseDto> {
    await this.exchange.sendEmailCode(body.email);
    return { success: true };
  }

  @Post('identity/email/verify-code')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({ summary: 'Exchange a verification code for a CipherBox identity token' })
  @ApiOkResponse({ type: IdentityTokenResponseDto })
  async verifyEmailCode(
    @Body() body: EmailCodeVerifyRequestDto
  ): Promise<IdentityTokenResponseDto> {
    return present(await this.exchange.fromEmailCode(body.email, body.code));
  }

  @Post('identity/wallet')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({
    summary: 'Exchange a SIWE signature for a CipherBox identity token (first-class first login)',
  })
  @ApiOkResponse({ type: IdentityTokenResponseDto })
  async wallet(@Body() body: SiweLoginRequestDto): Promise<IdentityTokenResponseDto> {
    return present(await this.exchange.fromWalletSignature(body.message, body.signature));
  }
}

function present(grant: IdentityGrant): IdentityTokenResponseDto {
  return {
    token: grant.token,
    verifierId: grant.verifierId,
    email: grant.email,
    expiresAt: grant.expiresAt.toISOString(),
  };
}
