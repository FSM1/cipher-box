import {
  Controller,
  Get,
  Post,
  Body,
  Header,
  HttpCode,
  HttpStatus,
  Logger,
  UnauthorizedException,
  OnModuleDestroy,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { UseGuards } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { parseSiweMessage } from 'viem/siwe';
import { JwtIssuerService } from '../services/jwt-issuer.service';
import { GoogleOAuthService } from '../services/google-oauth.service';
import { EmailOtpService } from '../services/email-otp.service';
import { SiweService } from '../services/siwe.service';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';
import {
  GoogleLoginDto,
  SendOtpDto,
  VerifyOtpDto,
  WalletVerifyDto,
  IdentityTokenResponseDto,
  SendOtpResponseDto,
} from '../dto/identity.dto';

@ApiTags('Identity')
@Controller('auth')
export class IdentityController implements OnModuleDestroy {
  private readonly logger = new Logger(IdentityController.name);
  private readonly redis: Redis;

  constructor(
    private jwtIssuerService: JwtIssuerService,
    private googleOAuthService: GoogleOAuthService,
    private emailOtpService: EmailOtpService,
    private siweService: SiweService,
    private configService: ConfigService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>
  ) {
    this.redis = new Redis({
      host: configService.get('REDIS_HOST', 'localhost'),
      port: configService.get<number>('REDIS_PORT', 6379),
      password: configService.get('REDIS_PASSWORD', undefined),
      lazyConnect: true,
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis.quit();
  }

  @Get('.well-known/jwks.json')
  @Header('Cache-Control', 'public, max-age=3600')
  @ApiOperation({ summary: 'JWKS endpoint for CipherBox identity provider' })
  @ApiResponse({
    status: 200,
    description: 'JWKS containing RS256 public key for JWT verification',
    schema: {
      type: 'object',
      properties: { keys: { type: 'array', items: { type: 'object' } } },
      required: ['keys'],
    },
  })
  getJwks(): { keys: object[] } {
    return this.jwtIssuerService.getJwksData();
  }

  @Post('identity/google')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login with Google OAuth token, returns CipherBox identity JWT',
  })
  @ApiResponse({
    status: 200,
    description: 'CipherBox JWT issued',
    type: IdentityTokenResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid Google token' })
  async googleLogin(@Body() dto: GoogleLoginDto): Promise<IdentityTokenResponseDto> {
    // 1. Verify Google token
    const googlePayload = await this.googleOAuthService.verifyGoogleToken(dto.idToken);
    const normalizedEmail = googlePayload.email?.toLowerCase().trim() ?? '';

    // 2. Link intent: just verify ownership and issue JWT (no user creation)
    if (dto.intent === 'link') {
      const idToken = await this.jwtIssuerService.signIdentityJwt(
        'link-verification',
        normalizedEmail
      );
      this.logger.log(`Google link verification: email=${normalizedEmail}`);
      return { idToken, userId: '', isNewUser: false, email: normalizedEmail };
    }

    // 3. Hash Google sub (immutable user ID) -- NOT email (which can change)
    const identifierHash = this.siweService.hashIdentifier(googlePayload.sub);

    // 4. Find or create user by hashed identifier
    const { user, isNewUser } = await this.findOrCreateUserByIdentifier(
      identifierHash,
      this.siweService.truncateEmail(normalizedEmail),
      'google'
    );

    // 5. Sign CipherBox identity JWT (include email for auth method identifier)
    const idToken = await this.jwtIssuerService.signIdentityJwt(user.id, normalizedEmail);

    this.logger.log(`Google login: userId=${user.id}, isNew=${isNewUser}`);

    return {
      idToken,
      userId: user.id,
      isNewUser,
      email: googlePayload.email,
    };
  }

  @Post('identity/email/send-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 900000 } }) // 5 requests per 15 min per IP
  @ApiOperation({ summary: 'Send OTP to email address' })
  @ApiResponse({
    status: 200,
    description: 'OTP sent',
    type: SendOtpResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid email or rate limit exceeded',
  })
  async sendOtp(@Body() dto: SendOtpDto): Promise<SendOtpResponseDto> {
    await this.emailOtpService.sendOtp(dto.email);
    return { success: true };
  }

  @Post('identity/email/verify-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 900000 } }) // 5 requests per 15 min per IP
  @ApiOperation({
    summary: 'Verify email OTP and return CipherBox identity JWT',
  })
  @ApiResponse({
    status: 200,
    description: 'OTP verified, JWT issued',
    type: IdentityTokenResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid or expired OTP' })
  async verifyOtp(@Body() dto: VerifyOtpDto): Promise<IdentityTokenResponseDto> {
    // 1. Verify OTP
    await this.emailOtpService.verifyOtp(dto.email, dto.otp);

    // 2. Normalize email
    const normalizedEmail = dto.email.toLowerCase().trim();

    // 3. Link intent: just verify ownership and issue JWT (no user creation)
    if (dto.intent === 'link') {
      const idToken = await this.jwtIssuerService.signIdentityJwt(
        'link-verification',
        normalizedEmail
      );
      this.logger.log(`Email link verification: email=${normalizedEmail}`);
      return { idToken, userId: '', isNewUser: false, email: normalizedEmail };
    }

    // 4. Hash for identifier lookup
    const identifierHash = this.siweService.hashIdentifier(normalizedEmail);

    // 5. Find or create user by hashed identifier
    const { user, isNewUser } = await this.findOrCreateUserByIdentifier(
      identifierHash,
      this.siweService.truncateEmail(normalizedEmail),
      'email'
    );

    // 6. Sign CipherBox identity JWT (include email for auth method identifier)
    const idToken = await this.jwtIssuerService.signIdentityJwt(user.id, normalizedEmail);

    this.logger.log(`Email OTP login: userId=${user.id}, isNew=${isNewUser}`);

    return {
      idToken,
      userId: user.id,
      isNewUser,
      email: normalizedEmail,
    };
  }

  @Get('identity/wallet/nonce')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 per 60s per IP
  @ApiOperation({ summary: 'Generate SIWE nonce for wallet login' })
  @ApiResponse({
    status: 200,
    description: 'Nonce generated',
    schema: {
      type: 'object',
      properties: { nonce: { type: 'string' } },
      required: ['nonce'],
    },
  })
  async getWalletNonce(): Promise<{ nonce: string }> {
    const nonce = this.siweService.generateNonce();
    // Store nonce in Redis with 5min TTL
    await this.redis.set(`siwe:nonce:${nonce}`, '1', 'EX', 300);
    return { nonce };
  }

  @Post('identity/wallet')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 900000 } }) // 5 per 15min per IP
  @ApiOperation({
    summary: 'Verify SIWE wallet signature and return CipherBox identity JWT',
  })
  @ApiResponse({
    status: 200,
    description: 'Wallet verified, JWT issued',
    type: IdentityTokenResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid nonce or signature' })
  async walletLogin(@Body() dto: WalletVerifyDto): Promise<IdentityTokenResponseDto> {
    // 1. Parse the message to extract nonce
    const parsed = parseSiweMessage(dto.message);
    if (!parsed.nonce) {
      throw new UnauthorizedException('Invalid SIWE message: missing nonce');
    }

    // 2. Consume nonce from Redis (single-use)
    const nonceKey = `siwe:nonce:${parsed.nonce}`;
    let nonceDeleted: number;
    try {
      nonceDeleted = await this.redis.del(nonceKey);
    } catch (err) {
      this.logger.error('Redis error during nonce consumption', err);
      throw new UnauthorizedException('Nonce verification failed');
    }
    if (!nonceDeleted) {
      throw new UnauthorizedException('Invalid or expired nonce');
    }

    // 3. Determine domain for validation
    const domain = this.configService.get<string>('SIWE_DOMAIN', 'localhost');

    // 4. Verify SIWE message + signature
    const walletAddress = await this.siweService.verifySiweMessage(
      dto.message,
      dto.signature as `0x${string}`,
      parsed.nonce,
      domain
    );

    // 5. Link intent: just verify ownership and issue JWT (no user creation)
    if (dto.intent === 'link') {
      const idToken = await this.jwtIssuerService.signIdentityJwt('link-verification');
      this.logger.log(`Wallet link verification: address=${walletAddress}`);
      return { idToken, userId: '', isNewUser: false };
    }

    // 6. Find or create user by wallet address hash
    const addressHash = this.siweService.hashWalletAddress(walletAddress);
    const truncated = this.siweService.truncateWalletAddress(walletAddress);
    const { user, isNewUser } = await this.findOrCreateUserByIdentifier(
      addressHash,
      truncated,
      'wallet'
    );

    // 7. Issue CipherBox JWT (sub=userId)
    const idToken = await this.jwtIssuerService.signIdentityJwt(user.id);

    this.logger.log(`Wallet login: userId=${user.id}, isNew=${isNewUser}`);

    return { idToken, userId: user.id, isNewUser };
  }

  /**
   * Find an existing user by hashed identifier in the AuthMethod table, or create a new user.
   *
   * Each auth method type is independent -- no cross-method email matching.
   * Users link methods explicitly via Settings, not auto-linked by email.
   *
   * For identity provider flow, the publicKey is set to a placeholder because
   * the actual MPC-derived publicKey is not known until the client completes
   * Core Kit login with the CipherBox JWT.
   */
  private async findOrCreateUserByIdentifier(
    identifierHash: string,
    identifierDisplay: string,
    authMethodType: 'google' | 'email' | 'wallet'
  ): Promise<{ user: User; isNewUser: boolean }> {
    // Look for existing auth method with this hash
    const existingMethod = await this.authMethodRepository.findOne({
      where: {
        type: authMethodType,
        identifierHash,
      },
      relations: ['user'],
    });

    if (existingMethod) {
      // Update last used timestamp
      existingMethod.lastUsedAt = new Date();
      await this.authMethodRepository.save(existingMethod);
      return { user: existingMethod.user, isNewUser: false };
    }

    // No cross-method linking -- create new user with unique temporary publicKey
    const tempId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const newUser = await this.userRepository.save({
      publicKey: `pending-core-kit-${tempId}`,
    });
    // Update placeholder with actual userId now that we have it
    newUser.publicKey = `pending-core-kit-${newUser.id}`;
    await this.userRepository.save(newUser);

    // Create auth method with hash-based identifier
    await this.authMethodRepository.save({
      userId: newUser.id,
      type: authMethodType,
      identifier: identifierHash,
      identifierHash,
      identifierDisplay,
      lastUsedAt: new Date(),
    });

    return { user: newUser, isNewUser: true };
  }
}
