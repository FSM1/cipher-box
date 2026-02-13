import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
  OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import * as argon2 from 'argon2';
import { randomInt } from 'crypto';

/** OTP validity in seconds */
const OTP_TTL = 300; // 5 minutes
/** Rate limit window in seconds */
const RATE_LIMIT_TTL = 900; // 15 minutes
/** Max OTP send attempts per email per rate limit window */
const MAX_SEND_ATTEMPTS = 5;
/** Max verification attempts per OTP */
const MAX_VERIFY_ATTEMPTS = 5;

@Injectable()
export class EmailOtpService implements OnModuleDestroy {
  private readonly logger = new Logger(EmailOtpService.name);
  private readonly redis: Redis;

  constructor(config: ConfigService) {
    this.redis = new Redis({
      host: config.get('REDIS_HOST', 'localhost'),
      port: config.get<number>('REDIS_PORT', 6379),
      password: config.get('REDIS_PASSWORD', undefined),
      lazyConnect: true,
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis.quit();
  }

  /**
   * Generate and store an OTP for the given email address.
   *
   * In non-production mode, the OTP is logged to console for testing.
   *
   * @throws BadRequestException if rate limit exceeded
   */
  async sendOtp(email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();

    // Check rate limit
    const rateLimitKey = `otp-attempts:${normalizedEmail}`;
    const attempts = await this.redis.get(rateLimitKey);
    if (attempts && parseInt(attempts, 10) >= MAX_SEND_ATTEMPTS) {
      throw new BadRequestException('Too many OTP requests. Please try again later.');
    }

    // Generate 6-digit OTP
    const otp = randomInt(100000, 1000000).toString();

    // Hash OTP before storing
    const hashedOtp = await argon2.hash(otp);

    // Store hashed OTP with TTL
    const otpKey = `otp:${normalizedEmail}`;
    await this.redis.setex(otpKey, OTP_TTL, hashedOtp);

    // Reset verify attempts for this new OTP
    const verifyKey = `otp-verify-attempts:${normalizedEmail}`;
    await this.redis.del(verifyKey);

    // Increment rate limit counter
    const currentAttempts = await this.redis.incr(rateLimitKey);
    if (currentAttempts === 1) {
      await this.redis.expire(rateLimitKey, RATE_LIMIT_TTL);
    }

    // Log OTP in development mode only (not staging, not production)
    if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
      this.logger.warn(`DEV OTP for ${normalizedEmail}: ${otp}`);
    }
  }

  /**
   * Verify an OTP for the given email address.
   *
   * On success, the OTP is deleted (single-use).
   *
   * @throws UnauthorizedException if OTP is invalid, expired, or too many attempts
   */
  async verifyOtp(email: string, otp: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();

    // Check verify attempt count
    const verifyKey = `otp-verify-attempts:${normalizedEmail}`;
    const verifyAttempts = await this.redis.get(verifyKey);
    if (verifyAttempts && parseInt(verifyAttempts, 10) >= MAX_VERIFY_ATTEMPTS) {
      // Delete the OTP to force re-request
      await this.redis.del(`otp:${normalizedEmail}`);
      throw new UnauthorizedException('Too many verification attempts. Please request a new code.');
    }

    // Retrieve stored hash
    const otpKey = `otp:${normalizedEmail}`;
    const storedHash = await this.redis.get(otpKey);

    if (!storedHash) {
      throw new UnauthorizedException('No OTP found. Please request a new code.');
    }

    // Increment verify attempt counter
    const currentVerifyAttempts = await this.redis.incr(verifyKey);
    if (currentVerifyAttempts === 1) {
      await this.redis.expire(verifyKey, OTP_TTL);
    }

    // Verify OTP against hash
    const isValid = await argon2.verify(storedHash, otp);
    if (!isValid) {
      throw new UnauthorizedException('Invalid OTP code.');
    }

    // OTP is valid -- delete it (single-use)
    await this.redis.del(otpKey);
    await this.redis.del(verifyKey);
  }
}
