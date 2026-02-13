import { Controller, Get, Post, Body, Header, HttpCode, HttpStatus, Logger } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { UseGuards } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtIssuerService } from '../services/jwt-issuer.service';
import { GoogleOAuthService } from '../services/google-oauth.service';
import { EmailOtpService } from '../services/email-otp.service';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';
import {
  GoogleLoginDto,
  SendOtpDto,
  VerifyOtpDto,
  IdentityTokenResponseDto,
  SendOtpResponseDto,
} from '../dto/identity.dto';

@ApiTags('Identity')
@Controller('auth')
export class IdentityController {
  private readonly logger = new Logger(IdentityController.name);

  constructor(
    private jwtIssuerService: JwtIssuerService,
    private googleOAuthService: GoogleOAuthService,
    private emailOtpService: EmailOtpService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>
  ) {}

  @Get('.well-known/jwks.json')
  @Header('Cache-Control', 'public, max-age=3600')
  @ApiOperation({ summary: 'JWKS endpoint for CipherBox identity provider' })
  @ApiResponse({
    status: 200,
    description: 'JWKS containing RS256 public key for JWT verification',
  })
  getJwks(): { keys: object[] } {
    return this.jwtIssuerService.getJwksData();
  }

  @Post('identity/google')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with Google OAuth token, returns CipherBox identity JWT' })
  @ApiResponse({ status: 200, description: 'CipherBox JWT issued', type: IdentityTokenResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid Google token' })
  async googleLogin(@Body() dto: GoogleLoginDto): Promise<IdentityTokenResponseDto> {
    // 1. Verify Google token
    const googlePayload = await this.googleOAuthService.verifyGoogleToken(dto.idToken);

    // 2. Find or create user by email
    const { user, isNewUser } = await this.findOrCreateUserByEmail(googlePayload.email, 'google');

    // 3. Sign CipherBox identity JWT (include email for auth method identifier)
    const idToken = await this.jwtIssuerService.signIdentityJwt(user.id, googlePayload.email);

    this.logger.log(`Google login: userId=${user.id}, isNew=${isNewUser}`);

    return { idToken, userId: user.id, isNewUser };
  }

  @Post('identity/email/send-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 900000 } }) // 5 requests per 15 min per IP
  @ApiOperation({ summary: 'Send OTP to email address' })
  @ApiResponse({ status: 200, description: 'OTP sent', type: SendOtpResponseDto })
  @ApiResponse({ status: 400, description: 'Invalid email or rate limit exceeded' })
  async sendOtp(@Body() dto: SendOtpDto): Promise<SendOtpResponseDto> {
    await this.emailOtpService.sendOtp(dto.email);
    return { success: true };
  }

  @Post('identity/email/verify-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 900000 } }) // 5 requests per 15 min per IP
  @ApiOperation({ summary: 'Verify email OTP and return CipherBox identity JWT' })
  @ApiResponse({
    status: 200,
    description: 'OTP verified, JWT issued',
    type: IdentityTokenResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid or expired OTP' })
  async verifyOtp(@Body() dto: VerifyOtpDto): Promise<IdentityTokenResponseDto> {
    // 1. Verify OTP
    await this.emailOtpService.verifyOtp(dto.email, dto.otp);

    // 2. Find or create user by email
    const { user, isNewUser } = await this.findOrCreateUserByEmail(dto.email, 'email_passwordless');

    // 3. Sign CipherBox identity JWT (include email for auth method identifier)
    const idToken = await this.jwtIssuerService.signIdentityJwt(user.id, dto.email);

    this.logger.log(`Email OTP login: userId=${user.id}, isNew=${isNewUser}`);

    return { idToken, userId: user.id, isNewUser };
  }

  /**
   * Find an existing user by email in the AuthMethod table, or create a new user.
   *
   * For identity provider flow, the publicKey is set to a placeholder because
   * the actual MPC-derived publicKey is not known until the client completes
   * Core Kit login with the CipherBox JWT.
   */
  private async findOrCreateUserByEmail(
    email: string,
    authMethodType: 'google' | 'email_passwordless'
  ): Promise<{ user: User; isNewUser: boolean }> {
    const normalizedEmail = email.toLowerCase().trim();

    // Look for existing auth method with this email
    const existingMethod = await this.authMethodRepository.findOne({
      where: {
        type: authMethodType,
        identifier: normalizedEmail,
      },
      relations: ['user'],
    });

    if (existingMethod) {
      // Update last used timestamp
      existingMethod.lastUsedAt = new Date();
      await this.authMethodRepository.save(existingMethod);
      return { user: existingMethod.user, isNewUser: false };
    }

    // Also check if this email exists under any auth method type
    // (e.g., user signed up with Google, now logging in with email)
    const anyMethodWithEmail = await this.authMethodRepository.findOne({
      where: { identifier: normalizedEmail },
      relations: ['user'],
    });

    if (anyMethodWithEmail) {
      // Same email, different auth method -- link to existing user
      await this.authMethodRepository.save({
        userId: anyMethodWithEmail.user.id,
        type: authMethodType,
        identifier: normalizedEmail,
        lastUsedAt: new Date(),
      });
      this.logger.log(`Linked ${authMethodType} to existing user ${anyMethodWithEmail.user.id}`);
      return { user: anyMethodWithEmail.user, isNewUser: false };
    }

    // Create new user with placeholder publicKey using userId (resolved in auth.service.ts)
    const newUser = await this.userRepository.save({
      publicKey: `pending-core-kit-placeholder`,
    });
    // Update placeholder with actual userId now that we have it
    newUser.publicKey = `pending-core-kit-${newUser.id}`;
    await this.userRepository.save(newUser);

    // Create auth method
    await this.authMethodRepository.save({
      userId: newUser.id,
      type: authMethodType,
      identifier: normalizedEmail,
      lastUsedAt: new Date(),
    });

    return { user: newUser, isNewUser: true };
  }
}
