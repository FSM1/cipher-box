import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException, BadRequestException, ForbiddenException } from '@nestjs/common';
import * as argon2 from 'argon2';
import * as jose from 'jose';
import { AuthService } from './auth.service';
import { JwtIssuerService } from './services/jwt-issuer.service';
import { TokenService } from './services/token.service';
import { SiweService } from './services/siwe.service';
import { User } from './entities/user.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';

describe('AuthService', () => {
  let service: AuthService;
  let configService: Record<string, jest.Mock>;
  let jwtIssuerService: Record<string, jest.Mock>;
  let tokenService: jest.Mocked<TokenService>;
  let siweService: Record<string, jest.Mock>;
  let userRepository: Record<string, jest.Mock>;
  let authMethodRepository: Record<string, jest.Mock>;
  let refreshTokenRepository: Record<string, jest.Mock>;

  beforeEach(async () => {
    const mockUserRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };

    const mockAuthMethodRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      save: jest.fn(),
      count: jest.fn(),
      remove: jest.fn(),
    };

    const mockRefreshTokenRepo = {
      find: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
    };

    const mockTokenService = {
      createTokens: jest.fn(),
      rotateRefreshToken: jest.fn(),
      revokeAllUserTokens: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn(),
    };

    const mockJwtIssuerService = {
      getJwksData: jest.fn(),
      signIdentityJwt: jest.fn(),
    };

    const mockSiweService = {
      generateNonce: jest.fn(),
      verifySiweMessage: jest.fn(),
      hashWalletAddress: jest.fn(),
      truncateWalletAddress: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: JwtIssuerService, useValue: mockJwtIssuerService },
        { provide: TokenService, useValue: mockTokenService },
        { provide: SiweService, useValue: mockSiweService },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: getRepositoryToken(AuthMethod), useValue: mockAuthMethodRepo },
        { provide: getRepositoryToken(RefreshToken), useValue: mockRefreshTokenRepo },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    configService = module.get(ConfigService);
    jwtIssuerService = module.get(JwtIssuerService);
    tokenService = module.get(TokenService);
    siweService = module.get(SiweService);
    userRepository = module.get(getRepositoryToken(User));
    authMethodRepository = module.get(getRepositoryToken(AuthMethod));
    refreshTokenRepository = module.get(getRepositoryToken(RefreshToken));
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('login', () => {
    const loginDto = {
      idToken: 'cipherbox-jwt',
      publicKey: 'abc123',
      loginType: 'corekit' as const,
    };

    it('should create new user on first login', async () => {
      const mockPayload = { sub: 'user-123', email: 'test@example.com' };
      const mockUser = { id: 'new-user-id', publicKey: 'abc123' };
      const mockAuthMethod = { id: 'am-1', userId: 'new-user-id', type: 'email' };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });
      userRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifier lookup
        .mockResolvedValueOnce(null); // userId fallback
      authMethodRepository.save
        .mockResolvedValueOnce(mockAuthMethod) // safety net create
        .mockResolvedValueOnce(mockAuthMethod); // lastUsedAt update
      tokenService.createTokens.mockResolvedValue(mockTokens);

      const result = await service.login(loginDto);

      expect(result.isNewUser).toBe(true);
      expect(result.accessToken).toBe('at');
      expect(result.refreshToken).toBe('rt');
      expect(userRepository.save).toHaveBeenCalledWith({
        publicKey: 'abc123',
      });
    });

    it('should return existing user on subsequent login', async () => {
      const mockPayload = { sub: 'user-123', email: 'test@example.com' };
      const mockUser = { id: 'existing-id', publicKey: 'abc123' };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'existing-id',
        type: 'google',
        identifier: 'test@example.com',
        lastUsedAt: null,
      };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      const result = await service.login(loginDto);

      expect(result.isNewUser).toBe(false);
      expect(result.accessToken).toBe('at');
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should update lastUsedAt on auth method', async () => {
      const mockPayload = { sub: 'user-123', email: 'test@example.com' };
      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'user-id',
        type: 'google',
        identifier: 'test@example.com',
        lastUsedAt: new Date('2020-01-01'),
      };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      await service.login(loginDto);

      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          lastUsedAt: expect.any(Date),
        })
      );
    });

    it('should throw UnauthorizedException if CipherBox JWT verification fails', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockRejectedValue(new Error('token expired'));

      await expect(service.login(loginDto)).rejects.toThrow(UnauthorizedException);
      expect(tokenService.createTokens).not.toHaveBeenCalled();
    });

    it('should handle non-Error thrown during JWT verification', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockRejectedValue('string-error');

      await expect(service.login(loginDto)).rejects.toThrow(UnauthorizedException);
    });

    it('should use sub as identifier when email is not present', async () => {
      const mockPayload = { sub: 'user-123' }; // no email

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(null);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifier lookup with sub
        .mockResolvedValueOnce(null); // userId fallback
      const savedMethod = {
        id: 'am-new',
        userId: 'user-id',
        type: 'email',
        identifier: 'user-123',
        lastUsedAt: null,
      };
      authMethodRepository.save.mockResolvedValue(savedMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          identifier: 'user-123',
        })
      );
    });

    it('should use unknown as identifier when neither email nor sub is present', async () => {
      const mockPayload = {}; // no email, no sub

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifier lookup
        .mockResolvedValueOnce(null); // userId fallback
      const savedMethod = {
        id: 'am-new',
        userId: 'user-id',
        type: 'email',
        identifier: 'unknown',
        lastUsedAt: null,
      };
      authMethodRepository.save.mockResolvedValue(savedMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          identifier: 'unknown',
        })
      );
    });

    it('should skip placeholder resolution when no verifierId or sub', async () => {
      const mockPayload = { email: 'test@example.com' }; // no sub, no verifierId

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      userRepository.findOne.mockResolvedValue(null); // no user found by publicKey, no placeholder search
      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValueOnce(null).mockResolvedValueOnce(null);
      authMethodRepository.save.mockResolvedValue({
        id: 'am-new',
        userId: 'user-id',
        type: 'email',
        identifier: 'test@example.com',
        lastUsedAt: null,
      });
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.login(loginDto);

      // Should create new user since placeholder search was skipped
      expect(result.isNewUser).toBe(true);
      // findOne called once for publicKey lookup, NOT for placeholder
      expect(userRepository.findOne).toHaveBeenCalledTimes(1);
    });

    it('should verify CipherBox JWT with correct parameters', async () => {
      const mockPayload = { sub: 'user-123', email: 'test@example.com' };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [{ kty: 'RSA' }] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      const mockAuthMethod = { id: 'am-1', userId: 'user-id', type: 'email' };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      const result = await service.login(loginDto);

      expect(jose.jwtVerify).toHaveBeenCalledWith('cipherbox-jwt', 'mock-jwks', {
        issuer: 'cipherbox',
        audience: 'web3auth',
        algorithms: ['RS256'],
      });
      expect(result.accessToken).toBe('at');
    });

    it('should resolve placeholder publicKey for corekit login', async () => {
      const corekitLoginDto = {
        idToken: 'cipherbox-jwt',
        publicKey: 'real-public-key',
        loginType: 'corekit' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: 'test@example.com' },
      });

      const placeholderUser = {
        id: 'user-id',
        publicKey: 'pending-core-kit-user-123-1234567890',
      };
      userRepository.findOne
        .mockResolvedValueOnce(null) // not found by real publicKey
        .mockResolvedValueOnce(placeholderUser); // found by placeholder
      userRepository.save.mockResolvedValue({
        ...placeholderUser,
        publicKey: 'real-public-key',
      });

      const mockAuthMethod = { id: 'am-1', userId: 'user-id', type: 'email' };
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.login(corekitLoginDto);

      expect(result.isNewUser).toBe(false);
      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ publicKey: 'real-public-key' })
      );
    });

    it('should find existing auth method by identifier (no duplicates)', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: 'test@example.com' },
      });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'user-id',
        type: 'google',
        identifier: 'test@example.com',
        lastUsedAt: null,
      };
      userRepository.findOne.mockResolvedValue(mockUser);
      // Identity controller already created a 'google' auth method for this user
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      // Should look up by userId + identifier, not hardcode type
      expect(authMethodRepository.findOne).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: 'user-id', identifier: 'test@example.com' },
        })
      );
    });

    it('should fall back to any auth method when identifier not found', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: 'test@example.com' },
      });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'user-id',
        type: 'google',
        identifier: 'different@example.com',
        lastUsedAt: null,
      };
      userRepository.findOne.mockResolvedValue(mockUser);
      // First authMethod findOne (by identifier): no match. Second (by userId only): found
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifier lookup - no match
        .mockResolvedValueOnce(mockAuthMethod); // userId fallback - found
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      // Second findOne should use userId only
      expect(authMethodRepository.findOne).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: 'user-id' },
        })
      );
    });

    it('should create auth method as safety net when none found', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: 'test@example.com' },
      });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.findOne.mockResolvedValue(mockUser);
      // Both lookups return null
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifier lookup
        .mockResolvedValueOnce(null); // userId fallback
      const savedMethod = {
        id: 'am-new',
        userId: 'user-id',
        type: 'email',
        identifier: 'test@example.com',
        lastUsedAt: null,
      };
      authMethodRepository.save.mockResolvedValue(savedMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      // Should create email as safety net
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'email',
          identifier: 'test@example.com',
        })
      );
    });

    it('should infer wallet type in safety net when identifier starts with 0x', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' },
      });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifier lookup
        .mockResolvedValueOnce(null); // userId fallback
      const savedMethod = {
        id: 'am-wallet',
        userId: 'user-id',
        type: 'wallet',
        identifier: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        lastUsedAt: null,
      };
      authMethodRepository.save.mockResolvedValue(savedMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'wallet',
          identifier: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        })
      );
    });
  });

  describe('refresh', () => {
    it('should call tokenService.rotateRefreshToken with correct params', async () => {
      const mockTokens = { accessToken: 'new-at', refreshToken: 'new-rt' };
      tokenService.rotateRefreshToken.mockResolvedValue(mockTokens);

      const result = await service.refresh('old-refresh-token', 'user-id', 'public-key');

      expect(tokenService.rotateRefreshToken).toHaveBeenCalledWith(
        'old-refresh-token',
        'user-id',
        'public-key'
      );
      expect(result.accessToken).toBe('new-at');
      expect(result.refreshToken).toBe('new-rt');
    });

    it('should return new tokens', async () => {
      const mockTokens = { accessToken: 'access-123', refreshToken: 'refresh-456' };
      tokenService.rotateRefreshToken.mockResolvedValue(mockTokens);

      const result = await service.refresh('token', 'user-id', 'key');

      expect(result).toEqual({
        accessToken: 'access-123',
        refreshToken: 'refresh-456',
      });
    });
  });

  describe('logout', () => {
    it('should revoke all user tokens', async () => {
      tokenService.revokeAllUserTokens.mockResolvedValue(undefined);

      await service.logout('user-id');

      expect(tokenService.revokeAllUserTokens).toHaveBeenCalledWith('user-id');
    });

    it('should return success: true', async () => {
      tokenService.revokeAllUserTokens.mockResolvedValue(undefined);

      const result = await service.logout('user-id');

      expect(result).toEqual({ success: true });
    });
  });

  describe('refreshByToken', () => {
    it('should find matching token by verifying argon2 hashes', async () => {
      const refreshToken = 'valid-refresh-token';
      const tokenHash = await argon2.hash(refreshToken);
      const mockToken = {
        id: 'token-id',
        userId: 'user-id',
        tokenHash,
        tokenPrefix: refreshToken.substring(0, 16),
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
        user: { id: 'user-id', publicKey: 'pub-key' },
      };
      const mockNewTokens = { accessToken: 'new-at', refreshToken: 'new-rt' };

      refreshTokenRepository.find.mockResolvedValue([mockToken]);
      refreshTokenRepository.save.mockResolvedValue({ ...mockToken, revokedAt: new Date() });
      tokenService.createTokens.mockResolvedValue(mockNewTokens);
      authMethodRepository.findOne.mockResolvedValue(null);

      const result = await service.refreshByToken(refreshToken);

      expect(result.accessToken).toBe('new-at');
      expect(result.refreshToken).toBe('new-rt');
    });

    it('should skip expired tokens', async () => {
      const refreshToken = 'valid-refresh-token';
      const tokenHash = await argon2.hash(refreshToken);
      const expiredToken = {
        id: 'expired-id',
        userId: 'user-id',
        tokenHash,
        tokenPrefix: refreshToken.substring(0, 16),
        expiresAt: new Date(Date.now() - 86400000),
        revokedAt: null,
        user: { id: 'user-id', publicKey: 'pub-key' },
      };

      refreshTokenRepository.find.mockResolvedValue([expiredToken]);

      await expect(service.refreshByToken(refreshToken)).rejects.toThrow(UnauthorizedException);
      await expect(service.refreshByToken(refreshToken)).rejects.toThrow(
        'Invalid or expired refresh token'
      );
    });

    it('should throw UnauthorizedException if no valid token found', async () => {
      refreshTokenRepository.find.mockResolvedValue([]);

      await expect(service.refreshByToken('invalid-token')).rejects.toThrow(UnauthorizedException);
      await expect(service.refreshByToken('invalid-token')).rejects.toThrow(
        'Invalid or expired refresh token'
      );
    });

    it('should revoke old token and create new tokens', async () => {
      const refreshToken = 'valid-refresh-token';
      const tokenHash = await argon2.hash(refreshToken);
      const mockToken = {
        id: 'token-id',
        userId: 'user-id',
        tokenHash,
        tokenPrefix: refreshToken.substring(0, 16),
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
        user: { id: 'user-id', publicKey: 'pub-key' },
      };
      const mockNewTokens = { accessToken: 'new-at', refreshToken: 'new-rt' };

      refreshTokenRepository.find.mockResolvedValue([mockToken]);
      refreshTokenRepository.save.mockResolvedValue({ ...mockToken, revokedAt: new Date() });
      tokenService.createTokens.mockResolvedValue(mockNewTokens);
      authMethodRepository.findOne.mockResolvedValue(null);

      await service.refreshByToken(refreshToken);

      expect(refreshTokenRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          revokedAt: expect.any(Date),
        })
      );
      expect(tokenService.createTokens).toHaveBeenCalledWith('user-id', 'pub-key');
    });

    it('should handle argon2.verify exceptions gracefully', async () => {
      const mockToken = {
        id: 'token-id',
        userId: 'user-id',
        tokenHash: 'invalid-hash-format',
        tokenPrefix: 'some-token-prefi',
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
        user: { id: 'user-id', publicKey: 'pub-key' },
      };

      refreshTokenRepository.find.mockResolvedValue([mockToken]);

      await expect(service.refreshByToken('some-token')).rejects.toThrow(UnauthorizedException);
    });

    it('should include email in response when email auth method exists', async () => {
      const refreshToken = 'valid-refresh-token';
      const tokenHash = await argon2.hash(refreshToken);
      const mockToken = {
        id: 'token-id',
        userId: 'user-id',
        tokenHash,
        tokenPrefix: refreshToken.substring(0, 16),
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
        user: { id: 'user-id', publicKey: 'pub-key' },
      };

      refreshTokenRepository.find.mockResolvedValue([mockToken]);
      refreshTokenRepository.save.mockResolvedValue({ ...mockToken, revokedAt: new Date() });
      tokenService.createTokens.mockResolvedValue({
        accessToken: 'new-at',
        refreshToken: 'new-rt',
      });
      authMethodRepository.findOne.mockResolvedValue({ identifier: 'test@example.com' });

      const result = await service.refreshByToken(refreshToken);

      expect(result.email).toBe('test@example.com');
      expect(authMethodRepository.findOne).toHaveBeenCalledWith({
        where: [
          { userId: 'user-id', type: 'email' },
          { userId: 'user-id', type: 'google' },
        ],
        order: { lastUsedAt: 'DESC' },
      });
    });
  });

  describe('getLinkedMethods', () => {
    it('should return list of auth methods ordered by createdAt', async () => {
      const mockMethods = [
        {
          id: 'am-1',
          type: 'google',
          identifier: 'test@example.com',
          identifierDisplay: null,
          lastUsedAt: new Date(),
          createdAt: new Date('2024-01-01'),
        },
        {
          id: 'am-2',
          type: 'email',
          identifier: 'user@example.com',
          identifierDisplay: null,
          lastUsedAt: null,
          createdAt: new Date('2024-02-01'),
        },
      ];

      authMethodRepository.find.mockResolvedValue(mockMethods);

      const result = await service.getLinkedMethods('user-id');

      expect(authMethodRepository.find).toHaveBeenCalledWith({
        where: { userId: 'user-id' },
        order: { createdAt: 'ASC' },
      });
      expect(result).toHaveLength(2);
      expect(result[0].type).toBe('google');
      expect(result[0].identifier).toBe('test@example.com');
      expect(result[1].type).toBe('email');
    });

    it('should return truncated display address for wallet methods', async () => {
      const mockMethods = [
        {
          id: 'am-1',
          type: 'wallet',
          identifier: 'sha256-hash-of-address',
          identifierDisplay: '0xAbCd...1234',
          identifierHash: 'sha256-hash-of-address',
          lastUsedAt: new Date(),
          createdAt: new Date('2024-01-01'),
        },
      ];

      authMethodRepository.find.mockResolvedValue(mockMethods);

      const result = await service.getLinkedMethods('user-id');

      expect(result).toHaveLength(1);
      expect(result[0].identifier).toBe('0xAbCd...1234');
    });

    it('should return empty array if no methods', async () => {
      authMethodRepository.find.mockResolvedValue([]);

      const result = await service.getLinkedMethods('user-id');

      expect(result).toEqual([]);
    });
  });

  describe('linkMethod', () => {
    const linkDto = {
      idToken: 'cipherbox-link-jwt',
      loginType: 'google' as const,
    };

    it('should verify CipherBox JWT and create new auth method', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };
      const mockMethod = {
        id: 'new-am',
        type: 'google',
        identifier: 'user@example.com',
        lastUsedAt: new Date(),
        createdAt: new Date(),
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(null);
      authMethodRepository.save.mockResolvedValue(mockMethod);
      authMethodRepository.find.mockResolvedValue([mockMethod]);

      const result = await service.linkMethod('user-id', linkDto);

      expect(jose.jwtVerify).toHaveBeenCalled();
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'google',
          identifier: 'user@example.com',
        })
      );
      expect(result).toHaveLength(1);
    });

    it('should throw BadRequestException if method already linked to same user', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };
      const existingMethod = { id: 'existing', type: 'google', identifier: 'user@example.com' };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      userRepository.findOne.mockResolvedValue(mockUser);
      // First findOne: cross-account check returns null (no other user has it)
      // Second findOne: same-user check returns existing method
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // cross-account
        .mockResolvedValueOnce(existingMethod); // same-user duplicate

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(BadRequestException);
      // Reset mocks for second assertion
      userRepository.findOne.mockResolvedValue(mockUser);
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });
      authMethodRepository.findOne
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(existingMethod);
      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(
        'This auth method is already linked to your account'
      );
    });

    it('should throw BadRequestException for cross-account collision (google/email)', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };
      const otherAccountMethod = {
        id: 'other-am',
        type: 'google',
        identifier: 'user@example.com',
        userId: 'other-user-id',
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      userRepository.findOne.mockResolvedValue(mockUser);
      // Cross-account check finds a method on a different user
      authMethodRepository.findOne.mockResolvedValueOnce(otherAccountMethod);

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(BadRequestException);
      // Reset for message check
      userRepository.findOne.mockResolvedValue(mockUser);
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });
      authMethodRepository.findOne.mockResolvedValueOnce(otherAccountMethod);
      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(
        'already linked to another account'
      );
    });

    it('should include "Google account" in cross-account collision message for google type', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValueOnce({
        id: 'other-am',
        type: 'google',
        identifier: 'user@example.com',
        userId: 'other-user-id',
      });

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow('Google account');
    });

    it('should include "email" in cross-account collision message for email type', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };
      const emailLinkDto = {
        idToken: 'cipherbox-link-jwt',
        loginType: 'email' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValueOnce({
        id: 'other-am',
        type: 'email',
        identifier: 'user@example.com',
        userId: 'other-user-id',
      });

      await expect(service.linkMethod('user-id', emailLinkDto)).rejects.toThrow('This email');
    });

    it('should throw UnauthorizedException if user not found', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(UnauthorizedException);
      userRepository.findOne.mockResolvedValue(null);
      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow('User not found');
    });

    it('should throw UnauthorizedException if CipherBox JWT verification fails during linking', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockRejectedValue(new Error('expired'));

      userRepository.findOne.mockResolvedValue(mockUser);

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(UnauthorizedException);
    });

    it('should link wallet method with SIWE verification', async () => {
      // Use a properly formatted EIP-4361 SIWE message so parseSiweMessage can extract the nonce
      const siweMessage = [
        'localhost wants you to sign in with your Ethereum account:',
        '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12',
        '',
        'Sign in to CipherBox encrypted storage',
        '',
        'URI: http://localhost:5173',
        'Version: 1',
        'Chain ID: 1',
        'Nonce: testnonce123',
        'Issued At: 2026-01-01T00:00:00.000Z',
      ].join('\n');

      const walletLinkDto = {
        idToken: '',
        loginType: 'wallet' as const,
        walletAddress: '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12',
        siweMessage,
        siweSignature: '0xmocksignature',
      };
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockMethod = {
        id: 'new-am',
        type: 'wallet',
        identifier: 'addr-hash',
        identifierDisplay: '0xAbCd...Ef12',
        lastUsedAt: new Date(),
        createdAt: new Date(),
      };

      userRepository.findOne.mockResolvedValue(mockUser);
      siweService.verifySiweMessage.mockResolvedValue('0xAbCdEf1234567890AbCdEf1234567890AbCdEf12');
      siweService.hashWalletAddress.mockReturnValue('addr-hash');
      siweService.truncateWalletAddress.mockReturnValue('0xAbCd...Ef12');
      authMethodRepository.findOne.mockResolvedValue(null); // no collision, no duplicate
      authMethodRepository.save.mockResolvedValue(mockMethod);
      authMethodRepository.find.mockResolvedValue([mockMethod]);

      const result = await service.linkMethod('user-id', walletLinkDto);

      expect(siweService.verifySiweMessage).toHaveBeenCalled();
      expect(siweService.hashWalletAddress).toHaveBeenCalled();
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'wallet',
          identifier: 'addr-hash',
          identifierHash: 'addr-hash',
          identifierDisplay: '0xAbCd...Ef12',
        })
      );
      expect(result).toHaveLength(1);
    });

    it('should throw BadRequestException for wallet cross-account collision', async () => {
      const siweMsg = [
        'localhost wants you to sign in with your Ethereum account:',
        '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12',
        '',
        'Sign in to CipherBox encrypted storage',
        '',
        'URI: http://localhost:5173',
        'Version: 1',
        'Chain ID: 1',
        'Nonce: testnonce123',
        'Issued At: 2026-01-01T00:00:00.000Z',
      ].join('\n');

      const walletLinkDto = {
        idToken: '',
        loginType: 'wallet' as const,
        walletAddress: '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12',
        siweMessage: siweMsg,
        siweSignature: '0xmocksignature',
      };
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };

      userRepository.findOne.mockResolvedValue(mockUser);
      siweService.verifySiweMessage.mockResolvedValue('0xAbCdEf1234567890AbCdEf1234567890AbCdEf12');
      siweService.hashWalletAddress.mockReturnValue('addr-hash');
      // Cross-account: wallet linked to different user
      authMethodRepository.findOne.mockResolvedValueOnce({
        id: 'other-am',
        userId: 'other-user-id',
      });

      await expect(service.linkMethod('user-id', walletLinkDto)).rejects.toThrow(
        BadRequestException
      );
    });

    it('should throw BadRequestException when wallet SIWE fields missing', async () => {
      const walletLinkDto = {
        idToken: '',
        loginType: 'wallet' as const,
        // Missing walletAddress, siweMessage, siweSignature
      };
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };

      userRepository.findOne.mockResolvedValue(mockUser);

      await expect(service.linkMethod('user-id', walletLinkDto)).rejects.toThrow(
        BadRequestException
      );
    });
  });

  describe('unlinkMethod', () => {
    it('should remove auth method', async () => {
      const mockMethod = { id: 'method-id', userId: 'user-id', type: 'google' };

      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      authMethodRepository.count.mockResolvedValue(2);
      authMethodRepository.remove.mockResolvedValue(mockMethod);

      await service.unlinkMethod('user-id', 'method-id');

      expect(authMethodRepository.remove).toHaveBeenCalledWith(mockMethod);
    });

    it('should throw BadRequestException if method not found', async () => {
      authMethodRepository.findOne.mockResolvedValue(null);

      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        BadRequestException
      );
      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        'Auth method not found'
      );
    });

    it('should throw BadRequestException if last auth method', async () => {
      const mockMethod = { id: 'method-id', userId: 'user-id', type: 'google' };

      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      authMethodRepository.count.mockResolvedValue(1);

      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        BadRequestException
      );
      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        'Cannot unlink your last auth method'
      );
    });
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

    it('should create new user on first test login', async () => {
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
          identifier: 'test@example.com', // normalized
        })
      );
    });

    it('should return existing user on subsequent test login', async () => {
      configService.get.mockReturnValue('test-secret');

      const mockUser = { id: 'existing-id', publicKey: 'matching-key' };
      const mockMethod = {
        id: 'am-1',
        userId: 'existing-id',
        type: 'email',
        identifier: 'test@example.com',
        user: mockUser,
        lastUsedAt: null,
      };
      authMethodRepository.findOne.mockResolvedValue(mockMethod);
      // The user's publicKey already matches (no save needed)
      authMethodRepository.save.mockResolvedValue(mockMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      // We need the generated key to match mockUser.publicKey for the "no update" path.
      // Since the key is deterministic, just allow any publicKey and check isNewUser.
      const result = await service.testLogin('test@example.com', 'test-secret');

      expect(result.isNewUser).toBe(false);
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

      // publicKey should have been updated (deterministic key != 'old-different-key')
      expect(userRepository.save).toHaveBeenCalled();
    });

    it('should generate deterministic keypair for same email', async () => {
      configService.get.mockReturnValue('test-secret');
      authMethodRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue({ id: 'id', publicKey: 'pk' });
      authMethodRepository.save.mockResolvedValue({});
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result1 = await service.testLogin('test@example.com', 'test-secret');

      // Reset mocks for second call
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
