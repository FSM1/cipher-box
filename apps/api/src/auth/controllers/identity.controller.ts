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

    // 2. Hash Google sub (immutable user ID) -- NOT email (which can change)
    const identifierHash = this.siweService.hashIdentifier(googlePayload.sub);

    // 3. Find or create user by hashed identifier
    const { user, isNewUser } = await this.findOrCreateUserByIdentifier(
      identifierHash,
      googlePayload.email,
      'google'
    );

    // 4. Sign CipherBox identity JWT (include email for auth method identifier)
    const idToken = await this.jwtIssuerService.signIdentityJwt(user.id, googlePayload.email);

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

    // 2. Normalize email and hash for identifier
    const normalizedEmail = dto.email.toLowerCase().trim();
    const identifierHash = this.siweService.hashIdentifier(normalizedEmail);

    // 3. Find or create user by hashed identifier
    const { user, isNewUser } = await this.findOrCreateUserByIdentifier(
      identifierHash,
      normalizedEmail,
      'email'
    );

    // 4. Sign CipherBox identity JWT (include email for auth method identifier)
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
    const nonceDeleted = await this.redis.del(nonceKey);
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

    // 5. Find or create user by wallet address hash
    const addressHash = this.siweService.hashWalletAddress(walletAddress);
    const { user, isNewUser } = await this.findOrCreateUserByWallet(addressHash, walletAddress);

    // 6. Issue CipherBox JWT (sub=userId)
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
    authMethodType: 'google' | 'email'
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

    // No cross-method linking -- create new user with placeholder publicKey
    const newUser = await this.userRepository.save({
      publicKey: `pending-core-kit-placeholder`,
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

  /**
   * Find an existing user by wallet address hash, or create a new user.
   *
   * Same placeholder publicKey pattern as findOrCreateUserByEmail.
   */
  private async findOrCreateUserByWallet(
    addressHash: string,
    walletAddress: string
  ): Promise<{ user: User; isNewUser: boolean }> {
    // Look for existing auth method with this wallet address hash
    const existingMethod = await this.authMethodRepository.findOne({
      where: {
        type: 'wallet',
        identifierHash: addressHash,
      },
      relations: ['user'],
    });

    if (existingMethod) {
      // Update last used timestamp
      existingMethod.lastUsedAt = new Date();
      await this.authMethodRepository.save(existingMethod);
      return { user: existingMethod.user, isNewUser: false };
    }

    // Create new user with placeholder publicKey
    const newUser = await this.userRepository.save({
      publicKey: `pending-core-kit-placeholder`,
    });
    newUser.publicKey = `pending-core-kit-${newUser.id}`;
    await this.userRepository.save(newUser);

    // Create wallet auth method with hash + truncated display
    const truncated = this.siweService.truncateWalletAddress(walletAddress);
    await this.authMethodRepository.save({
      userId: newUser.id,
      type: 'wallet',
      identifier: addressHash, // hash stored as identifier for consistency
      identifierHash: addressHash,
      identifierDisplay: truncated,
      lastUsedAt: new Date(),
    });

    return { user: newUser, isNewUser: true };
  }
}
