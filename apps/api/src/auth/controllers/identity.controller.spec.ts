import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ThrottlerGuard } from '@nestjs/throttler';
import { IdentityController } from './identity.controller';
import { JwtIssuerService } from '../services/jwt-issuer.service';
import { GoogleOAuthService } from '../services/google-oauth.service';
import { EmailOtpService } from '../services/email-otp.service';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';

describe('IdentityController', () => {
  let controller: IdentityController;
  let jwtIssuerService: Record<string, jest.Mock>;
  let googleOAuthService: Record<string, jest.Mock>;
  let emailOtpService: Record<string, jest.Mock>;
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

    const mockUserRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };

    const mockAuthMethodRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IdentityController],
      providers: [
        { provide: JwtIssuerService, useValue: mockJwtIssuerService },
        { provide: GoogleOAuthService, useValue: mockGoogleOAuthService },
        { provide: EmailOtpService, useValue: mockEmailOtpService },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: getRepositoryToken(AuthMethod), useValue: mockAuthMethodRepo },
      ],
    })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<IdentityController>(IdentityController);
    jwtIssuerService = module.get(JwtIssuerService);
    googleOAuthService = module.get(GoogleOAuthService);
    emailOtpService = module.get(EmailOtpService);
    userRepository = module.get(getRepositoryToken(User));
    authMethodRepository = module.get(getRepositoryToken(AuthMethod));
  });

  afterEach(() => {
    jest.resetAllMocks();
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
    it('should verify Google token and return CipherBox JWT for new user', async () => {
      googleOAuthService.verifyGoogleToken.mockResolvedValue({
        email: 'user@gmail.com',
        sub: 'google-123',
      });

      // No existing auth method — new user
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // by type + identifier
        .mockResolvedValueOnce(null); // by any identifier

      const mockUser = { id: 'new-user-id' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue({});
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.googleLogin({ idToken: 'google-token' });

      expect(result.idToken).toBe('cipherbox-jwt');
      expect(result.userId).toBe('new-user-id');
      expect(result.isNewUser).toBe(true);
      expect(googleOAuthService.verifyGoogleToken).toHaveBeenCalledWith('google-token');
      expect(jwtIssuerService.signIdentityJwt).toHaveBeenCalledWith(
        'new-user-id',
        'user@gmail.com'
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

      const result = await controller.googleLogin({ idToken: 'google-token' });

      expect(result.isNewUser).toBe(false);
      expect(result.userId).toBe('existing-id');
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
      emailOtpService.verifyOtp.mockResolvedValue(undefined);

      // No existing auth method — new user
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // by type + identifier
        .mockResolvedValueOnce(null); // by any identifier

      const mockUser = { id: 'new-user-id' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue({});
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.verifyOtp({
        email: 'test@example.com',
        otp: '123456',
      });

      expect(result.idToken).toBe('cipherbox-jwt');
      expect(result.userId).toBe('new-user-id');
      expect(result.isNewUser).toBe(true);
      expect(emailOtpService.verifyOtp).toHaveBeenCalledWith('test@example.com', '123456');
    });

    it('should link to existing user when email matches different auth type', async () => {
      emailOtpService.verifyOtp.mockResolvedValue(undefined);

      // No existing email_passwordless method
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // by email_passwordless type
        .mockResolvedValueOnce({
          // found by any identifier (google method with same email)
          user: { id: 'existing-id' },
        });

      authMethodRepository.save.mockResolvedValue({});
      jwtIssuerService.signIdentityJwt.mockResolvedValue('cipherbox-jwt');

      const result = await controller.verifyOtp({
        email: 'test@example.com',
        otp: '123456',
      });

      expect(result.isNewUser).toBe(false);
      expect(result.userId).toBe('existing-id');
      // Should have saved a new email_passwordless auth method for existing user
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'existing-id',
          type: 'email_passwordless',
          identifier: 'test@example.com',
        })
      );
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
});
