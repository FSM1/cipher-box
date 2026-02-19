import { UnauthorizedException, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { EmailOtpService } from './email-otp.service';

// Mock ioredis
const mockRedis = {
  get: jest.fn(),
  setex: jest.fn(),
  del: jest.fn(),
  incr: jest.fn(),
  expire: jest.fn(),
  quit: jest.fn(),
};

jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => mockRedis);
});

// Mock @sendgrid/mail — use require() to get mock reference after jest.mock hoisting
jest.mock('@sendgrid/mail', () => ({
  __esModule: true,
  default: {
    setApiKey: jest.fn(),
    send: jest.fn().mockResolvedValue([{ statusCode: 202 }]),
  },
}));
// eslint-disable-next-line @typescript-eslint/no-require-imports
const mockSgMail = require('@sendgrid/mail').default;

describe('EmailOtpService', () => {
  let service: EmailOtpService;
  let configService: { get: jest.Mock };

  beforeEach(() => {
    configService = { get: jest.fn().mockReturnValue(undefined) };
    service = new EmailOtpService(configService as unknown as ConfigService);
    jest.clearAllMocks();
  });

  describe('sendOtp', () => {
    it('should generate and store hashed OTP', async () => {
      mockRedis.get.mockResolvedValue(null);
      mockRedis.incr.mockResolvedValue(1);

      await service.sendOtp('test@example.com');

      // Should store hashed OTP (not plaintext)
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'otp:test@example.com',
        300, // 5 min TTL
        expect.any(String)
      );
      // Should reset verify attempts
      expect(mockRedis.del).toHaveBeenCalledWith('otp-verify-attempts:test@example.com');
      // Should increment rate limit
      expect(mockRedis.incr).toHaveBeenCalledWith('otp-attempts:test@example.com');
    });

    it('should normalize email to lowercase', async () => {
      mockRedis.get.mockResolvedValue(null);
      mockRedis.incr.mockResolvedValue(1);

      await service.sendOtp('Test@EXAMPLE.com');

      expect(mockRedis.setex).toHaveBeenCalledWith(
        'otp:test@example.com',
        expect.any(Number),
        expect.any(String)
      );
    });

    it('should set expiry on first rate limit increment', async () => {
      mockRedis.get.mockResolvedValue(null);
      mockRedis.incr.mockResolvedValue(1);

      await service.sendOtp('test@example.com');

      expect(mockRedis.expire).toHaveBeenCalledWith('otp-attempts:test@example.com', 900);
    });

    it('should not set expiry on subsequent rate limit increments', async () => {
      mockRedis.get.mockResolvedValue(null);
      mockRedis.incr.mockResolvedValue(3);

      await service.sendOtp('test@example.com');

      expect(mockRedis.expire).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException when rate limit exceeded', async () => {
      mockRedis.get.mockResolvedValue('5');

      await expect(service.sendOtp('test@example.com')).rejects.toThrow(BadRequestException);
      await expect(service.sendOtp('test@example.com')).rejects.toThrow(
        'Too many OTP requests. Please try again later.'
      );
    });

    it('should send email via SendGrid when configured', async () => {
      // Create a service instance with SendGrid configured
      const sgConfigService = {
        get: jest.fn((key: string, defaultValue?: unknown) => {
          if (key === 'SENDGRID_API_KEY') return 'SG.test-api-key';
          if (key === 'SENDGRID_FROM_EMAIL') return 'test@cipherbox.cc';
          return defaultValue;
        }),
      };
      const sgService = new EmailOtpService(sgConfigService as unknown as ConfigService);

      mockRedis.get.mockResolvedValueOnce(null); // rate limit check
      mockRedis.incr.mockResolvedValueOnce(1);
      mockSgMail.send.mockResolvedValueOnce([{ statusCode: 202 }]);

      await sgService.sendOtp('user@example.com');

      expect(mockSgMail.send).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          from: 'test@cipherbox.cc',
          subject: 'Your CipherBox verification code',
          text: expect.stringContaining('verification code is:'),
          html: expect.stringContaining('verification code is:'),
        })
      );
    });

    it('should not send email when SendGrid is not configured', async () => {
      mockRedis.get.mockResolvedValueOnce(null); // rate limit check
      mockRedis.incr.mockResolvedValueOnce(1);

      await service.sendOtp('test@example.com');

      expect(mockSgMail.send).not.toHaveBeenCalled();
    });

    it('should not throw when SendGrid send fails', async () => {
      // Create a service instance with SendGrid configured
      const sgConfigService = {
        get: jest.fn((key: string, defaultValue?: unknown) => {
          if (key === 'SENDGRID_API_KEY') return 'SG.test-api-key';
          if (key === 'SENDGRID_FROM_EMAIL') return 'test@cipherbox.cc';
          return defaultValue;
        }),
      };
      const sgService = new EmailOtpService(sgConfigService as unknown as ConfigService);

      mockRedis.get.mockResolvedValueOnce(null); // rate limit check
      mockRedis.incr.mockResolvedValueOnce(1);
      mockSgMail.send.mockRejectedValueOnce(new Error('SendGrid error'));

      // Should not throw — OTP is stored in Redis regardless
      await expect(sgService.sendOtp('user@example.com')).resolves.toBeUndefined();

      // OTP should still be stored in Redis
      expect(mockRedis.setex).toHaveBeenCalledWith('otp:user@example.com', 300, expect.any(String));
    });
  });

  describe('verifyOtp', () => {
    it('should verify valid OTP and delete it', async () => {
      const otp = '123456';
      const hashedOtp = await argon2.hash(otp);

      mockRedis.get
        .mockResolvedValueOnce(null) // verify attempts
        .mockResolvedValueOnce(hashedOtp); // stored OTP hash
      mockRedis.incr.mockResolvedValue(1);

      await service.verifyOtp('test@example.com', otp);

      // Should delete OTP (single-use) and verify attempts
      expect(mockRedis.del).toHaveBeenCalledWith('otp:test@example.com');
      expect(mockRedis.del).toHaveBeenCalledWith('otp-verify-attempts:test@example.com');
    });

    it('should throw UnauthorizedException for invalid OTP', async () => {
      const hashedOtp = await argon2.hash('123456');

      mockRedis.get
        .mockResolvedValueOnce(null) // verify attempts
        .mockResolvedValueOnce(hashedOtp); // stored OTP hash
      mockRedis.incr.mockResolvedValue(1);

      await expect(service.verifyOtp('test@example.com', 'wrong-otp')).rejects.toThrow(
        'Invalid OTP code.'
      );
    });

    it('should throw UnauthorizedException if no OTP found', async () => {
      mockRedis.get
        .mockResolvedValueOnce(null) // verify attempts
        .mockResolvedValueOnce(null); // no stored OTP
      mockRedis.incr.mockResolvedValue(1);

      await expect(service.verifyOtp('test@example.com', '123456')).rejects.toThrow(
        'No OTP found. Please request a new code.'
      );
    });

    it('should throw UnauthorizedException when too many verify attempts', async () => {
      mockRedis.get.mockResolvedValueOnce('5'); // max attempts reached

      await expect(service.verifyOtp('test@example.com', '123456')).rejects.toThrow(
        UnauthorizedException
      );
      await expect(service.verifyOtp('test@example.com', '123456')).rejects.toThrow(
        'Too many verification attempts. Please request a new code.'
      );
      // Should also delete the OTP
      expect(mockRedis.del).toHaveBeenCalledWith('otp:test@example.com');
    });

    it('should set expiry on first verify attempt', async () => {
      const hashedOtp = await argon2.hash('123456');

      mockRedis.get
        .mockResolvedValueOnce(null) // verify attempts
        .mockResolvedValueOnce(hashedOtp);
      mockRedis.incr.mockResolvedValue(1);

      await service.verifyOtp('test@example.com', '123456');

      expect(mockRedis.expire).toHaveBeenCalledWith('otp-verify-attempts:test@example.com', 300);
    });
  });

  describe('onModuleDestroy', () => {
    it('should quit redis connection', async () => {
      await service.onModuleDestroy();

      expect(mockRedis.quit).toHaveBeenCalled();
    });
  });
});
