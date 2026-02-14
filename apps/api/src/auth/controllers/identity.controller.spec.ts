import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { createHash } from 'crypto';
import { IdentityController } from './identity.controller';
import { JwtIssuerService } from '../services/jwt-issuer.service';
import { GoogleOAuthService } from '../services/google-oauth.service';
import { EmailOtpService } from '../services/email-otp.service';
import { SiweService } from '../services/siwe.service';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';

// Mock ioredis
const mockRedis = {
  set: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  quit: jest.fn(),
};
jest.mock('ioredis', () => jest.fn(() => mockRedis));

// Mock viem/siwe
const mockParseSiweMessage = jest.fn();
jest.mock('viem/siwe', () => ({
  parseSiweMessage: (...args: unknown[]) => mockParseSiweMessage(...args),
}));

/** Helper: compute expected SHA-256 hex hash */
function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

describe('IdentityController', () => {
  let controller: IdentityController;
  let jwtIssuerService: Record<string, jest.Mock>;
  let googleOAuthService: Record<string, jest.Mock>;
  let emailOtpService: Record<string, jest.Mock>;
  let siweService: Record<string, jest.Mock>;
  let userRepository: Record<string, jest.Mock>;
  let authMethodRepository: Record<string, jest.Mock>;

  beforeEach(async () => {
    const mockJwtIssuerService = {
      getJwksData: jest.fn(),
      signIdentityJwt: jest.fn(),
    };

    const mockGoogleOAuthService = {
      verifyGoogleToken: jest.fn(),
    };

    const mockEmailOtpService = {
      sendOtp: jest.fn(),
      verifyOtp: jest.fn(),
    };

    const mockSiweService = {
      generateNonce: jest.fn(),
      verifySiweMessage: jest.fn(),
      hashWalletAddress: jest.fn(),
      hashIdentifier: jest.fn((value: string) => sha256Hex(value)),
      truncateWalletAddress: jest.fn(),
    };

    const mockUserRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };

    const mockAuthMethodRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn((key: string, defaultValue?: unknown) => {
        if (key === 'REDIS_HOST') return 'localhost';
        if (key === 'REDIS_PORT') return 6379;
        if (key === 'REDIS_PASSWORD') return undefined;
        if (key === 'SIWE_DOMAIN') return 'localhost';
        return defaultValue;
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IdentityController],
      providers: [
        { provide: JwtIssuerService, useValue: mockJwtIssuerService },
        { provide: GoogleOAuthService, useValue: mockGoogleOAuthService },
        { provide: EmailOtpService, useValue: mockEmailOtpService },
        { provide: SiweService, useValue: mockSiweService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        {
          provide: getRepositoryToken(AuthMethod),
          useValue: mockAuthMethodRepo,
        },
      ],
    })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<IdentityController>(IdentityController);
    jwtIssuerService = module.get(JwtIssuerService);
    googleOAuthService = module.get(GoogleOAuthService);
    emailOtpService = module.get(EmailOtpService);
    siweService = module.get(SiweService);
    userRepository = module.get(getRepositoryToken(User));
    authMethodRepository = module.get(getRepositoryToken(AuthMethod));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getJwks', () => {
    it('should return JWKS data from jwt issuer service', () => {
      const mockJwks = { keys: [{ kty: 'RSA', kid: 'test-key' }] };
      jwtIssuerService.getJwksData.mockReturnValue(mockJwks);

      const result = controller.getJwks();

      expect(result).toEqual(mockJwks);
      expect(jwtIssuerService.getJwksData).toHaveBeenCalled();
    });
  });

  describe('googleLogin', () => {
    it('should hash googlePayload.sub (not email) and create new user', async () => {
      const googleSub = 'google-123';
      const googleEmail = 'user@gmail.com';
      const expectedHash = sha256Hex(googleSub);

      googleOAuthService.verifyGoogleToken.mockResolvedValue({
        email: googleEmail,
        sub: googleSub,
      });

      // No existing auth method -- new user
      authMethodRepository.findOne.mockResolvedValue(null);

      const mockUser = { id: 'new-user-id' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue({});
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.googleLogin({
        idToken: 'google-token',
      });

      expect(result.idToken).toBe('cipherbox-jwt');
      expect(result.userId).toBe('new-user-id');
      expect(result.isNewUser).toBe(true);
      expect(result.email).toBe(googleEmail);
      expect(googleOAuthService.verifyGoogleToken).toHaveBeenCalledWith('google-token');
      // Verify hashIdentifier was called with sub (NOT email)
      expect(siweService.hashIdentifier).toHaveBeenCalledWith(googleSub);
      expect(jwtIssuerService.signIdentityJwt).toHaveBeenCalledWith('new-user-id', googleEmail);
      // Verify auth method created with hash + display
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          identifier: expectedHash,
          identifierHash: expectedHash,
          identifierDisplay: googleEmail,
          type: 'google',
        })
      );
    });

    it('should return existing user on subsequent Google login', async () => {
      googleOAuthService.verifyGoogleToken.mockResolvedValue({
        email: 'user@gmail.com',
        sub: 'google-123',
      });

      const mockUser = { id: 'existing-id' };
      const mockMethod = {
        user: mockUser,
        lastUsedAt: null,
      };
      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      authMethodRepository.save.mockResolvedValue(mockMethod);
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.googleLogin({
        idToken: 'google-token',
      });

      expect(result.isNewUser).toBe(false);
      expect(result.userId).toBe('existing-id');
      // Should look up by identifierHash
      expect(authMethodRepository.findOne).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            type: 'google',
            identifierHash: sha256Hex('google-123'),
          }),
        })
      );
    });
  });

  describe('sendOtp', () => {
    it('should delegate to emailOtpService', async () => {
      emailOtpService.sendOtp.mockResolvedValue(undefined);

      const result = await controller.sendOtp({ email: 'test@example.com' });

      expect(result).toEqual({ success: true });
      expect(emailOtpService.sendOtp).toHaveBeenCalledWith('test@example.com');
    });
  });

  describe('verifyOtp', () => {
    it('should verify OTP and return CipherBox JWT for new user', async () => {
      const email = 'test@example.com';
      const expectedHash = sha256Hex(email);

      emailOtpService.verifyOtp.mockResolvedValue(undefined);

      // No existing auth method -- new user
      authMethodRepository.findOne.mockResolvedValue(null);

      const mockUser = { id: 'new-user-id' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue({});
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.verifyOtp({
        email,
        otp: '123456',
      });

      expect(result.idToken).toBe('cipherbox-jwt');
      expect(result.userId).toBe('new-user-id');
      expect(result.isNewUser).toBe(true);
      expect(emailOtpService.verifyOtp).toHaveBeenCalledWith(email, '123456');
      // Verify auth method created with hash + display
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          identifier: expectedHash,
          identifierHash: expectedHash,
          identifierDisplay: email,
          type: 'email',
        })
      );
    });

    it('should create SEPARATE user when email matches existing Google user (no auto-linking)', async () => {
      const email = 'shared@example.com';

      emailOtpService.verifyOtp.mockResolvedValue(undefined);

      // No existing email auth method with this hash
      authMethodRepository.findOne.mockResolvedValue(null);

      const mockUser = { id: 'new-email-user-id' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue({});
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.verifyOtp({
        email,
        otp: '123456',
      });

      // Should create a NEW user, not link to existing Google user
      expect(result.isNewUser).toBe(true);
      expect(result.userId).toBe('new-email-user-id');
      // findOne should only be called once (by type + identifierHash), NOT a second time for cross-method
      expect(authMethodRepository.findOne).toHaveBeenCalledTimes(1);
    });

    it('should return existing user on subsequent email login', async () => {
      emailOtpService.verifyOtp.mockResolvedValue(undefined);

      const mockUser = { id: 'existing-id' };
      const mockMethod = { user: mockUser, lastUsedAt: null };
      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      authMethodRepository.save.mockResolvedValue(mockMethod);
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.verifyOtp({
        email: 'test@example.com',
        otp: '123456',
      });

      expect(result.isNewUser).toBe(false);
      expect(result.userId).toBe('existing-id');
    });
  });

  describe('getWalletNonce', () => {
    it('should generate nonce and store in Redis with TTL', async () => {
      siweService.generateNonce.mockReturnValue('abc123def456');
      mockRedis.set.mockResolvedValue('OK');

      const result = await controller.getWalletNonce();

      expect(result).toEqual({ nonce: 'abc123def456' });
      expect(siweService.generateNonce).toHaveBeenCalled();
      expect(mockRedis.set).toHaveBeenCalledWith('siwe:nonce:abc123def456', '1', 'EX', 300);
    });
  });

  describe('walletLogin', () => {
    const testMessage = 'localhost wants you to sign in...';
    const testSignature = '0xabc123';
    const testAddress = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    const testHash = 'sha256hash';
    const testNonce = 'validnonce123';

    it('should verify SIWE and return JWT for new wallet user', async () => {
      mockParseSiweMessage.mockReturnValue({
        nonce: testNonce,
        address: testAddress,
      });
      mockRedis.del.mockResolvedValue(1); // nonce exists and deleted

      siweService.verifySiweMessage.mockResolvedValue(testAddress);
      siweService.hashWalletAddress.mockReturnValue(testHash);
      siweService.truncateWalletAddress.mockReturnValue('0xd8dA...6045');

      // No existing wallet auth method
      authMethodRepository.findOne.mockResolvedValue(null);

      const mockUser = { id: 'new-wallet-user-id' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue({});
      jwtIssuerService.signIdentityJwt.mockResolvedValue('wallet-jwt');

      const result = await controller.walletLogin({
        message: testMessage,
        signature: testSignature,
      });

      expect(result.idToken).toBe('wallet-jwt');
      expect(result.userId).toBe('new-wallet-user-id');
      expect(result.isNewUser).toBe(true);
      expect(mockRedis.del).toHaveBeenCalledWith(`siwe:nonce:${testNonce}`);
      expect(siweService.verifySiweMessage).toHaveBeenCalled();
      expect(siweService.hashWalletAddress).toHaveBeenCalledWith(testAddress);
    });

    it('should return existing user for known wallet', async () => {
      mockParseSiweMessage.mockReturnValue({
        nonce: testNonce,
        address: testAddress,
      });
      mockRedis.del.mockResolvedValue(1);

      siweService.verifySiweMessage.mockResolvedValue(testAddress);
      siweService.hashWalletAddress.mockReturnValue(testHash);

      const mockUser = { id: 'existing-wallet-user' };
      const mockMethod = {
        user: mockUser,
        lastUsedAt: null,
      };
      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      authMethodRepository.save.mockResolvedValue(mockMethod);
      jwtIssuerService.signIdentityJwt.mockResolvedValue('wallet-jwt');

      const result = await controller.walletLogin({
        message: testMessage,
        signature: testSignature,
      });

      expect(result.isNewUser).toBe(false);
      expect(result.userId).toBe('existing-wallet-user');
    });

    it('should throw 401 for invalid or expired nonce', async () => {
      mockParseSiweMessage.mockReturnValue({
        nonce: 'expired-nonce',
        address: testAddress,
      });
      mockRedis.del.mockResolvedValue(0); // nonce not found

      await expect(
        controller.walletLogin({
          message: testMessage,
          signature: testSignature,
        })
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw 401 for invalid SIWE signature', async () => {
      mockParseSiweMessage.mockReturnValue({
        nonce: testNonce,
        address: testAddress,
      });
      mockRedis.del.mockResolvedValue(1);

      siweService.verifySiweMessage.mockRejectedValue(
        new UnauthorizedException('Invalid SIWE signature')
      );

      await expect(
        controller.walletLogin({
          message: testMessage,
          signature: testSignature,
        })
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});
