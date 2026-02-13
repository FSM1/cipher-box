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
import sgMail from '@sendgrid/mail';

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
  private readonly sendgridConfigured: boolean;
  private readonly sendgridFromEmail: string;

  constructor(config: ConfigService) {
    this.redis = new Redis({
      host: config.get('REDIS_HOST', 'localhost'),
      port: config.get<number>('REDIS_PORT', 6379),
      password: config.get('REDIS_PASSWORD', undefined),
      lazyConnect: true,
    });

    const apiKey = config.get<string>('SENDGRID_API_KEY', '');
    this.sendgridFromEmail = config.get<string>('SENDGRID_FROM_EMAIL', 'noreply@cipherbox.cc');

    if (apiKey) {
      sgMail.setApiKey(apiKey);
      this.sendgridConfigured = true;
      this.logger.log('SendGrid email delivery enabled');
    } else {
      this.sendgridConfigured = false;
      this.logger.log('SendGrid not configured — OTP codes will be logged in dev mode only');
    }
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

    // Send OTP email via SendGrid (if configured)
    if (this.sendgridConfigured) {
      try {
        await sgMail.send({
          to: normalizedEmail,
          from: this.sendgridFromEmail,
          subject: 'Your CipherBox verification code',
          text: `Your CipherBox verification code is: ${otp}\n\nThis code expires in 5 minutes. If you did not request this code, please ignore this email.`,
          html: `<p>Your CipherBox verification code is:</p><p style="font-size:24px;font-weight:bold;letter-spacing:4px;margin:16px 0">${otp}</p><p>This code expires in 5 minutes. If you did not request this code, please ignore this email.</p>`,
        });
        this.logger.log(`OTP email sent to ${normalizedEmail}`);
      } catch (error) {
        // Do not throw — OTP is already stored in Redis, user can retry
        this.logger.error(`Failed to send OTP email to ${normalizedEmail}`, (error as Error).stack);
      }
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
