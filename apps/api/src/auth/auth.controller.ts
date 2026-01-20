import { Controller, Post, Body, HttpCode, HttpStatus, UseGuards, Request } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto, LoginResponseDto } from './dto/login.dto';
import { RefreshDto, TokenResponseDto, LogoutResponseDto } from './dto/token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { User } from './entities/user.entity';

interface RequestWithUser extends Request {
  user: User;
}

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Authenticate user with Web3Auth ID token' })
  @ApiResponse({
    status: 200,
    description: 'Successfully authenticated',
    type: LoginResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid Web3Auth token' })
  async login(@Body() loginDto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(loginDto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  @ApiResponse({
    status: 200,
    description: 'Tokens refreshed successfully',
    type: TokenResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  async refresh(@Body() refreshDto: RefreshDto): Promise<TokenResponseDto> {
    // For refresh, we need to decode the access token to get userId
    // Since the access token might be expired, we'll need to verify refresh token
    // by checking against all user tokens and extract userId from matching token
    // This is handled in TokenService.rotateRefreshToken

    // For now, refresh requires a valid (possibly expired) access token in header
    // to identify the user. Alternative: Include userId in refresh DTO.
    // Following spec: we verify refresh token against stored hashes for the user.

    // The spec says POST /auth/refresh accepts { refreshToken } and rotates.
    // We need to find which user owns this token by checking all active tokens.
    // This is O(n*m) but refresh tokens are short-lived and users have few active tokens.

    // For simplicity, let's modify to accept userId in body as well,
    // or search across all users. The second is more standard for refresh flows.

    // Actually, looking at the plan more carefully:
    // The plan says "rotates refresh token" which implies we know the user.
    // Most auth flows either:
    // 1. Include the access token (even if expired) to get user identity
    // 2. Search all tokens to find the owner

    // Let's implement option 2 for better UX (no expired token needed)
    return this.authService.refreshByToken(refreshDto.refreshToken);
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
  async logout(@Request() req: RequestWithUser): Promise<LogoutResponseDto> {
    return this.authService.logout(req.user.id);
  }
}
