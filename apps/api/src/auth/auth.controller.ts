import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { AuthMetricsInterceptor } from './auth-metrics.interceptor';
import {
  AuthMethodDto,
  ChallengeRequestDto,
  ChallengeResponseDto,
  HEX_REFRESH_TOKEN,
  LoginRequestDto,
  LogoutResponseDto,
  RefreshRequestDto,
  SiweChallengeResponseDto,
  SiweLinkRequestDto,
  StepUpChallengeRequestDto,
  TestLoginRequestDto,
  TestLoginResponseDto,
  TokenResponseDto,
  UnlinkMethodRequestDto,
} from './dto/auth.dto';
import { AuthenticatedRequest, JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthService } from './services/auth.service';
import { TestAuthService } from './services/test-auth.service';
import { TokenService } from './services/token.service';

const REFRESH_COOKIE = 'refreshToken';

/**
 * The account identity key the session already proved. Every route that mints
 * or spends an account-management challenge reads the key here, never from the
 * request body, so a caller cannot aim one at another account.
 */
function accountKey(request: AuthenticatedRequest): string {
  const { publicKey } = request.user;
  if (!publicKey) {
    throw new ForbiddenException('Insufficient token scope');
  }
  return publicKey;
}

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  private readonly cookieSecure: boolean;

  constructor(
    private readonly authService: AuthService,
    private readonly testAuthService: TestAuthService,
    private readonly tokenService: TokenService,
    configService: ConfigService
  ) {
    const nodeEnv = configService.get<string>('NODE_ENV') ?? 'development';
    this.cookieSecure = nodeEnv !== 'development' && nodeEnv !== 'test';
  }

  @Post('challenge')
  @UseInterceptors(AuthMetricsInterceptor)
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({
    summary:
      'Issue a single-use login challenge bound to an identity publicKey; POST /auth/login is the only route that accepts it',
  })
  @ApiOkResponse({ type: ChallengeResponseDto })
  challenge(@Body() body: ChallengeRequestDto): ChallengeResponseDto {
    const { challenge, expiresAt } = this.authService.issueIdentityChallenge(body.publicKey);
    return { challenge, expiresAt: expiresAt.toISOString() };
  }

  @Post('challenge/step-up')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary:
      'Issue a single-use challenge that authorises one account-management operation and no other',
  })
  @ApiOkResponse({ type: ChallengeResponseDto })
  stepUpChallenge(
    @Body() body: StepUpChallengeRequestDto,
    @Req() request: AuthenticatedRequest
  ): ChallengeResponseDto {
    const { challenge, expiresAt } = this.authService.issueStepUpChallenge(
      accountKey(request),
      body.operation,
      body.methodId
    );
    return { challenge, expiresAt: expiresAt.toISOString() };
  }

  @Post('login')
  @UseInterceptors(AuthMetricsInterceptor)
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({
    summary:
      'Challenge-signature login against the secp256k1 identity key; creates the account implicitly at first login',
  })
  @ApiOkResponse({ type: TokenResponseDto })
  async login(
    @Body() body: LoginRequestDto,
    @Res({ passthrough: true }) response: Response
  ): Promise<TokenResponseDto> {
    const { pair, isNewUser } = await this.authService.identityLogin(
      body.publicKey,
      body.challenge,
      body.signature
    );
    this.setRefreshCookie(response, pair.refreshToken);
    return { ...pair, isNewUser };
  }

  @Post('siwe/challenge')
  @UseInterceptors(AuthMetricsInterceptor)
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({
    summary: 'Issue a single-use SIWE nonce for a wallet sign-in; the link route refuses it',
  })
  @ApiOkResponse({ type: SiweChallengeResponseDto })
  siweChallenge(): SiweChallengeResponseDto {
    const { nonce, expiresAt } = this.authService.issueSiweNonce('siwe-login');
    return { nonce, expiresAt: expiresAt.toISOString() };
  }

  @Post('siwe/link-challenge')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Issue a single-use SIWE nonce that only POST /auth/siwe/link will accept',
  })
  @ApiOkResponse({ type: SiweChallengeResponseDto })
  siweLinkChallenge(@Req() request: AuthenticatedRequest): SiweChallengeResponseDto {
    const { nonce, expiresAt } = this.authService.issueSiweNonce('siwe-link', accountKey(request));
    return { nonce, expiresAt: expiresAt.toISOString() };
  }

  @Post('siwe/link')
  @Throttle(THROTTLE_SURFACES.auth)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Link a SIWE wallet to the authenticated account, re-proving the account identity key',
  })
  @ApiCreatedResponse({ type: LogoutResponseDto })
  async siweLink(
    @Body() body: SiweLinkRequestDto,
    @Req() request: AuthenticatedRequest
  ): Promise<LogoutResponseDto> {
    const publicKey = accountKey(request);
    await this.authService.siweLink(
      request.user.userId,
      publicKey,
      body.message,
      body.signature,
      body.challenge,
      body.challengeSignature
    );
    return { success: true };
  }

  @Get('methods')
  @Throttle(THROTTLE_SURFACES.account)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'List the login methods on the authenticated account, in display form only',
  })
  @ApiOkResponse({ type: AuthMethodDto, isArray: true })
  listMethods(@Req() request: AuthenticatedRequest): Promise<AuthMethodDto[]> {
    return this.authService.listAuthMethods(request.user.userId);
  }

  @Post('unlink')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Unlink one login method, re-proving the account identity key',
  })
  @ApiOkResponse({ type: LogoutResponseDto })
  async unlink(
    @Body() body: UnlinkMethodRequestDto,
    @Req() request: AuthenticatedRequest
  ): Promise<LogoutResponseDto> {
    await this.authService.unlinkAuthMethod(
      request.user.userId,
      accountKey(request),
      body.methodId,
      body.challenge,
      body.signature
    );
    return { success: true };
  }

  @Post('refresh')
  @UseInterceptors(AuthMetricsInterceptor)
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.refresh)
  @ApiOperation({
    summary: 'Rotate the refresh token (one-time-use; reuse revokes the whole family)',
  })
  @ApiOkResponse({ type: TokenResponseDto })
  async refresh(
    @Body() body: RefreshRequestDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response
  ): Promise<TokenResponseDto> {
    const cookies = (request as Request & { cookies?: Record<string, string> }).cookies;
    const rawToken = body.refreshToken ?? cookies?.[REFRESH_COOKIE];
    // The cookie path skips DTO validation — hold it to the same shape the
    // body field enforces so both paths reject malformed tokens alike.
    if (!rawToken || !HEX_REFRESH_TOKEN.test(rawToken)) {
      throw new UnauthorizedException('Missing refresh token');
    }
    const pair = await this.authService.refresh(rawToken);
    this.setRefreshCookie(response, pair.refreshToken);
    return pair;
  }

  @Post('logout')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Revoke every refresh token for the account (hard delete)' })
  @ApiOkResponse({ type: LogoutResponseDto })
  async logout(
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response
  ): Promise<LogoutResponseDto> {
    await this.authService.logout(request.user.userId);
    response.clearCookie(REFRESH_COOKIE, { path: '/auth' });
    return { success: true };
  }

  @Post('test-login')
  @UseInterceptors(AuthMetricsInterceptor)
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.auth)
  @ApiOperation({
    summary: 'Staging-gated deterministic login for e2e (hard-blocked in production)',
  })
  @ApiOkResponse({ type: TestLoginResponseDto })
  async testLogin(
    @Body() body: TestLoginRequestDto,
    @Res({ passthrough: true }) response: Response
  ): Promise<TestLoginResponseDto> {
    const result = await this.testAuthService.testLogin(body.handle, body.secret);
    this.setRefreshCookie(response, result.refreshToken);
    return result;
  }

  private setRefreshCookie(response: Response, refreshToken: string): void {
    response.cookie(REFRESH_COOKIE, refreshToken, {
      httpOnly: true,
      secure: this.cookieSecure,
      sameSite: 'strict',
      path: '/auth',
      maxAge: this.tokenService.refreshTokenTtlMs,
    });
  }
}
