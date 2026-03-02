import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { createHash } from 'crypto';
import { TestAuthService } from './test-auth.service';
import { TokenService } from './token.service';
import { SiweService } from './siwe.service';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';

/** Helper: compute expected SHA-256 hex hash */
function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

describe('TestAuthService', () => {
  let service: TestAuthService;
  let configService: Record<string, jest.Mock>;
  let tokenService: jest.Mocked<TokenService>;
  let userRepository: Record<string, jest.Mock>;
  let authMethodRepository: Record<string, jest.Mock>;

  beforeEach(async () => {
    const mockUserRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };

    const mockAuthMethodRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };

    const mockTokenService = {
      createTokens: jest.fn(),
      rotateRefreshToken: jest.fn(),
      revokeAllUserTokens: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn(),
    };

    const mockSiweService = {
      hashIdentifier: jest.fn((value: string) => createHash('sha256').update(value).digest('hex')),
      truncateEmail: jest.fn((email: string) => {
        const at = email.indexOf('@');
        if (at === -1) return email;
        const local = email.slice(0, at);
        const domain = email.slice(at);
        if (local.length <= 5) return email;
        return `${local.slice(0, 3)}...${local.slice(-2)}${domain}`;
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TestAuthService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: TokenService, useValue: mockTokenService },
        { provide: SiweService, useValue: mockSiweService },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: getRepositoryToken(AuthMethod), useValue: mockAuthMethodRepo },
      ],
    }).compile();

    service = module.get<TestAuthService>(TestAuthService);
    configService = module.get(ConfigService);
    tokenService = module.get(TokenService);
    userRepository = module.get(getRepositoryToken(User));
    authMethodRepository = module.get(getRepositoryToken(AuthMethod));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('testLogin', () => {
    it('should throw ForbiddenException in production environment', async () => {
      configService.get.mockImplementation((key: string) => {
        if (key === 'NODE_ENV') return 'production';
        return 'test-secret';
      });

      await expect(service.testLogin('test@example.com', 'test-secret')).rejects.toThrow(
        ForbiddenException
      );
      await expect(service.testLogin('test@example.com', 'test-secret')).rejects.toThrow(
        'Test login is not available in production'
      );
    });

    it('should throw ForbiddenException if TEST_LOGIN_SECRET not set', async () => {
      configService.get.mockReturnValue(undefined);

      await expect(service.testLogin('test@example.com', 'any-secret')).rejects.toThrow(
        ForbiddenException
      );
    });

    it('should throw UnauthorizedException if secret does not match', async () => {
      configService.get.mockReturnValue('correct-secret');

      await expect(service.testLogin('test@example.com', 'wrong-secret')).rejects.toThrow(
        UnauthorizedException
      );
    });

    it('should create new user with hashed identifier on first test login', async () => {
      const normalizedEmail = 'test@example.com';
      const identifierHash = sha256Hex(normalizedEmail);

      configService.get.mockReturnValue('test-secret');
      authMethodRepository.findOne.mockResolvedValue(null);

      const mockUser = { id: 'new-user-id', publicKey: 'generated-pubkey' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue({
        id: 'am-1',
        userId: 'new-user-id',
        type: 'email',
      });
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.testLogin('Test@Example.com', 'test-secret');

      expect(result.isNewUser).toBe(true);
      expect(result.accessToken).toBe('at');
      expect(result.refreshToken).toBe('rt');
      expect(result.publicKeyHex).toBeDefined();
      expect(result.privateKeyHex).toBeDefined();
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'email',
          identifier: identifierHash,
          identifierHash,
          identifierDisplay: normalizedEmail,
        })
      );
    });

    it('should look up by identifierHash on subsequent test login', async () => {
      const normalizedEmail = 'test@example.com';
      const identifierHash = sha256Hex(normalizedEmail);

      configService.get.mockReturnValue('test-secret');

      const mockUser = { id: 'existing-id', publicKey: 'matching-key' };
      const mockMethod = {
        id: 'am-1',
        userId: 'existing-id',
        type: 'email',
        identifier: identifierHash,
        identifierHash,
        identifierDisplay: normalizedEmail,
        user: mockUser,
        lastUsedAt: null,
      };
      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      authMethodRepository.save.mockResolvedValue(mockMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.testLogin(normalizedEmail, 'test-secret');

      expect(result.isNewUser).toBe(false);
      expect(authMethodRepository.findOne).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { type: 'email', identifierHash },
        })
      );
    });

    it('should update publicKey if different from existing', async () => {
      configService.get.mockReturnValue('test-secret');

      const mockUser = { id: 'user-id', publicKey: 'old-different-key' };
      const mockMethod = {
        user: mockUser,
        lastUsedAt: null,
      };
      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.save.mockResolvedValue(mockMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.testLogin('test@example.com', 'test-secret');

      expect(userRepository.save).toHaveBeenCalled();
    });

    it('should generate deterministic keypair for same email', async () => {
      configService.get.mockReturnValue('test-secret');
      authMethodRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue({ id: 'id', publicKey: 'pk' });
      authMethodRepository.save.mockResolvedValue({});
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result1 = await service.testLogin('test@example.com', 'test-secret');

      authMethodRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue({ id: 'id2', publicKey: 'pk' });
      authMethodRepository.save.mockResolvedValue({});
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at2', refreshToken: 'rt2' });

      const result2 = await service.testLogin('test@example.com', 'test-secret');

      expect(result1.publicKeyHex).toBe(result2.publicKeyHex);
      expect(result1.privateKeyHex).toBe(result2.privateKeyHex);
    });

    it('should generate different keypair for different emails', async () => {
      configService.get.mockReturnValue('test-secret');
      authMethodRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue({ id: 'id', publicKey: 'pk' });
      authMethodRepository.save.mockResolvedValue({});
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result1 = await service.testLogin('user1@example.com', 'test-secret');

      authMethodRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue({ id: 'id2', publicKey: 'pk' });
      authMethodRepository.save.mockResolvedValue({});
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at2', refreshToken: 'rt2' });

      const result2 = await service.testLogin('user2@example.com', 'test-secret');

      expect(result1.publicKeyHex).not.toBe(result2.publicKeyHex);
      expect(result1.privateKeyHex).not.toBe(result2.privateKeyHex);
    });
  });
});
