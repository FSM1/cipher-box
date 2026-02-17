import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Request,
  Res,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Response, Request as ExpressRequest } from 'express';
import { AuthService } from './auth.service';
import { LoginDto, LoginResponseDto } from './dto/login.dto';
import { TokenResponseDto, DesktopRefreshDto, LogoutResponseDto } from './dto/token.dto';
import { TestLoginDto, TestLoginResponseDto } from './dto/test-login.dto';
import {
  LinkMethodDto,
  AuthMethodResponseDto,
  UnlinkMethodDto,
  UnlinkMethodResponseDto,
} from './dto/link-method.dto';
import { ThrottlerGuard } from '@nestjs/throttler';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { User } from './entities/user.entity';

interface RequestWithUser extends Request {
  user: User;
}

// Cookie configuration
const REFRESH_TOKEN_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/auth', // Only sent to auth endpoints
};

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiOperation({ summary: 'Authenticate user with Web3Auth ID token' })
  @ApiResponse({
    status: 200,
    description: 'Successfully authenticated',
    type: LoginResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid Web3Auth token' })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: ExpressRequest,
    @Res({ passthrough: true }) res: Response
  ): Promise<LoginResponseDto> {
    const result = await this.authService.login(loginDto);
    const isDesktop = req.headers['x-client-type'] === 'desktop';

    if (isDesktop) {
      // Desktop clients: return refreshToken in response body (no cookie)
      return {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        isNewUser: result.isNewUser,
      };
    }

    // Web clients: set refresh token in HTTP-only cookie
    res.cookie('refresh_token', result.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

    return {
      accessToken: result.accessToken,
      isNewUser: result.isNewUser,
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token using HTTP-only refresh token cookie' })
  @ApiResponse({
    status: 200,
    description: 'Tokens refreshed successfully',
    type: TokenResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  async refresh(
    @Req() req: ExpressRequest,
    @Body() body: DesktopRefreshDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<TokenResponseDto> {
    const isDesktop = req.headers['x-client-type'] === 'desktop';

    let refreshToken: string | undefined;

    if (isDesktop) {
      // Desktop clients: read refresh token from request body
      refreshToken = body?.refreshToken;
    } else {
      // Web clients: read refresh token from cookie
      refreshToken = req.cookies?.['refresh_token'];
    }

    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token');
    }

    const result = await this.authService.refreshByToken(refreshToken);

    if (isDesktop) {
      // Desktop clients: return new refreshToken in response body (no cookie)
      return {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        email: result.email,
      };
    }

    // Web clients: set new refresh token in HTTP-only cookie (rotation)
    res.cookie('refresh_token', result.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

    return {
      accessToken: result.accessToken,
      email: result.email,
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user and invalidate all refresh tokens' })
  @ApiResponse({
    status: 200,
    description: 'Successfully logged out',
    type: LogoutResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(
    @Request() req: RequestWithUser,
    @Res({ passthrough: true }) res: Response
  ): Promise<LogoutResponseDto> {
    const isDesktop = (req as unknown as ExpressRequest).headers['x-client-type'] === 'desktop';

    if (!isDesktop) {
      // Web clients: clear the refresh token cookie
      res.clearCookie('refresh_token', { path: '/auth' });
    }

    return this.authService.logout(req.user.id);
  }

  @Get('methods')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get all linked auth methods for the current user' })
  @ApiResponse({
    status: 200,
    description: 'List of linked auth methods',
    type: [AuthMethodResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getMethods(@Request() req: RequestWithUser): Promise<AuthMethodResponseDto[]> {
    return this.authService.getLinkedMethods(req.user.id);
  }

  @Post('link')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Link a new auth method to the current user account' })
  @ApiResponse({
    status: 200,
    description: 'Auth method linked successfully, returns updated list of methods',
    type: [AuthMethodResponseDto],
  })
  @ApiResponse({ status: 400, description: 'Auth method already linked or publicKey mismatch' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async linkMethod(
    @Request() req: RequestWithUser,
    @Body() linkDto: LinkMethodDto
  ): Promise<AuthMethodResponseDto[]> {
    return this.authService.linkMethod(req.user.id, linkDto);
  }

  @Post('unlink')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Unlink an auth method from the current user account' })
  @ApiResponse({
    status: 200,
    description: 'Auth method unlinked successfully',
    type: UnlinkMethodResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Cannot unlink last auth method or method not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async unlinkMethod(
    @Request() req: RequestWithUser,
    @Body() unlinkDto: UnlinkMethodDto
  ): Promise<UnlinkMethodResponseDto> {
    await this.authService.unlinkMethod(req.user.id, unlinkDto.methodId);
    return { success: true };
  }

  @Post('test-login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 900000 } })
  @ApiOperation({
    summary: 'Test-only login bypassing Core Kit (requires TEST_LOGIN_SECRET)',
  })
  @ApiResponse({
    status: 200,
    description: 'Test login successful',
    type: TestLoginResponseDto,
  })
  @ApiResponse({ status: 403, description: 'Test login not enabled' })
  @ApiResponse({ status: 401, description: 'Invalid secret' })
  async testLogin(
    @Body() dto: TestLoginDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<TestLoginResponseDto> {
    const result = await this.authService.testLogin(dto.email, dto.secret);

    // Set refresh token cookie (same as normal login for web clients)
    res.cookie('refresh_token', result.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      isNewUser: result.isNewUser,
      publicKeyHex: result.publicKeyHex,
      privateKeyHex: result.privateKeyHex,
    };
  }
}
