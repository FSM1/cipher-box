import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException, BadRequestException, ForbiddenException } from '@nestjs/common';
import * as argon2 from 'argon2';
import * as jose from 'jose';
import { AuthService } from './auth.service';
import { Web3AuthVerifierService } from './services/web3auth-verifier.service';
import { JwtIssuerService } from './services/jwt-issuer.service';
import { TokenService } from './services/token.service';
import { User } from './entities/user.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';

describe('AuthService', () => {
  let service: AuthService;
  let configService: Record<string, jest.Mock>;
  let web3AuthVerifier: jest.Mocked<Web3AuthVerifierService>;
  let jwtIssuerService: Record<string, jest.Mock>;
  let tokenService: jest.Mocked<TokenService>;
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

    const mockWeb3AuthVerifier = {
      verifyIdToken: jest.fn(),
      extractAuthMethodType: jest.fn(),
      extractIdentifier: jest.fn(),
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

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: Web3AuthVerifierService, useValue: mockWeb3AuthVerifier },
        { provide: JwtIssuerService, useValue: mockJwtIssuerService },
        { provide: TokenService, useValue: mockTokenService },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: getRepositoryToken(AuthMethod), useValue: mockAuthMethodRepo },
        { provide: getRepositoryToken(RefreshToken), useValue: mockRefreshTokenRepo },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    configService = module.get(ConfigService);
    web3AuthVerifier = module.get(Web3AuthVerifierService);
    jwtIssuerService = module.get(JwtIssuerService);
    tokenService = module.get(TokenService);
    userRepository = module.get(getRepositoryToken(User));
    authMethodRepository = module.get(getRepositoryToken(AuthMethod));
    refreshTokenRepository = module.get(getRepositoryToken(RefreshToken));
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('login', () => {
    const loginDto = {
      idToken: 'valid-token',
      publicKey: 'abc123',
      loginType: 'social' as const,
    };

    it('should create new user on first login', async () => {
      const mockPayload = { verifier: 'google', email: 'test@example.com' };
      const mockUser = { id: 'new-user-id', publicKey: 'abc123', derivationVersion: null };
      const mockAuthMethod = { id: 'am-1', userId: 'new-user-id', type: 'google' };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('google');
      web3AuthVerifier.extractIdentifier.mockReturnValue('test@example.com');
      userRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(null);
      authMethodRepository.save
        .mockResolvedValueOnce(mockAuthMethod)
        .mockResolvedValueOnce(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      const result = await service.login(loginDto);

      expect(result.isNewUser).toBe(true);
      expect(result.accessToken).toBe('at');
      expect(result.refreshToken).toBe('rt');
      expect(userRepository.save).toHaveBeenCalledWith({
        publicKey: 'abc123',
        derivationVersion: null,
      });
    });

    it('should return existing user on subsequent login', async () => {
      const mockPayload = { verifier: 'google', email: 'test@example.com' };
      const mockUser = { id: 'existing-id', publicKey: 'abc123', derivationVersion: null };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'existing-id',
        type: 'google',
        lastUsedAt: null,
      };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('google');
      web3AuthVerifier.extractIdentifier.mockReturnValue('test@example.com');
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      const result = await service.login(loginDto);

      expect(result.isNewUser).toBe(false);
      expect(result.accessToken).toBe('at');
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should update derivation version for external wallets', async () => {
      const externalLoginDto = {
        idToken: 'valid-token',
        publicKey: 'derived-key',
        loginType: 'external_wallet' as const,
        walletAddress: '0x123abc',
        derivationVersion: 1,
      };
      const mockPayload = { wallets: [{ type: 'ethereum', address: '0x123abc' }] };
      const mockExistingUser = {
        id: 'user-id',
        publicKey: 'derived-key',
        derivationVersion: null,
      };
      const mockUpdatedUser = { id: 'user-id', publicKey: 'derived-key', derivationVersion: 1 };
      const mockAuthMethod = { id: 'am-1', userId: 'user-id', type: 'external_wallet' };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('external_wallet');
      web3AuthVerifier.extractIdentifier.mockReturnValue('0x123abc');
      userRepository.findOne.mockResolvedValue(mockExistingUser);
      userRepository.save.mockResolvedValue(mockUpdatedUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      await service.login(externalLoginDto);

      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          derivationVersion: 1,
        })
      );
    });

    it('should create auth method if not exists', async () => {
      const mockPayload = { verifier: 'google', email: 'new@example.com' };
      const mockUser = { id: 'user-id', publicKey: 'abc123', derivationVersion: null };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('google');
      web3AuthVerifier.extractIdentifier.mockReturnValue('new@example.com');
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(null);
      authMethodRepository.save.mockResolvedValue({ id: 'am-new', type: 'google' });
      tokenService.createTokens.mockResolvedValue(mockTokens);

      await service.login(loginDto);

      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'google',
          identifier: 'new@example.com',
        })
      );
    });

    it('should update lastUsedAt on auth method', async () => {
      const mockPayload = { verifier: 'google', email: 'test@example.com' };
      const mockUser = { id: 'user-id', publicKey: 'abc123', derivationVersion: null };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'user-id',
        type: 'google',
        lastUsedAt: new Date('2020-01-01'),
      };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('google');
      web3AuthVerifier.extractIdentifier.mockReturnValue('test@example.com');
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

    it('should throw if Web3Auth token verification fails', async () => {
      web3AuthVerifier.verifyIdToken.mockRejectedValue(
        new UnauthorizedException('Invalid Web3Auth token')
      );

      await expect(service.login(loginDto)).rejects.toThrow(UnauthorizedException);
      expect(tokenService.createTokens).not.toHaveBeenCalled();
    });

    it('should use walletAddress for verification when loginType is external_wallet', async () => {
      const externalLoginDto = {
        idToken: 'valid-token',
        publicKey: 'derived-key',
        loginType: 'external_wallet' as const,
        walletAddress: '0x123abc',
        derivationVersion: 1,
      };
      const mockPayload = { wallets: [{ type: 'ethereum', address: '0x123abc' }] };
      const mockUser = { id: 'user-id', publicKey: 'derived-key', derivationVersion: 1 };
      const mockAuthMethod = { id: 'am-1', userId: 'user-id', type: 'external_wallet' };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('external_wallet');
      web3AuthVerifier.extractIdentifier.mockReturnValue('0x123abc');
      userRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(null);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      await service.login(externalLoginDto);

      expect(web3AuthVerifier.verifyIdToken).toHaveBeenCalledWith(
        'valid-token',
        '0x123abc',
        'external_wallet'
      );
    });

    it('should verify CipherBox JWT for corekit login type', async () => {
      const corekitLoginDto = {
        idToken: 'cipherbox-jwt',
        publicKey: 'abc123',
        loginType: 'corekit' as const,
      };
      const mockJwksData = { keys: [{ kty: 'RSA' }] };
      const mockPayload = { sub: 'user-123', email: 'test@example.com' };

      jwtIssuerService.getJwksData.mockReturnValue(mockJwksData);
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      const mockUser = { id: 'user-id', publicKey: 'abc123', derivationVersion: null };
      const mockAuthMethod = { id: 'am-1', userId: 'user-id', type: 'email_passwordless' };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      const result = await service.login(corekitLoginDto);

      expect(jose.jwtVerify).toHaveBeenCalledWith('cipherbox-jwt', 'mock-jwks', {
        issuer: 'cipherbox',
        audience: 'web3auth',
        algorithms: ['RS256'],
      });
      expect(result.accessToken).toBe('at');
      expect(web3AuthVerifier.verifyIdToken).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException if CipherBox JWT verification fails', async () => {
      const corekitLoginDto = {
        idToken: 'bad-jwt',
        publicKey: 'abc123',
        loginType: 'corekit' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockRejectedValue(new Error('token expired'));

      await expect(service.login(corekitLoginDto)).rejects.toThrow(UnauthorizedException);
      expect(tokenService.createTokens).not.toHaveBeenCalled();
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
        derivationVersion: null,
      };
      userRepository.findOne
        .mockResolvedValueOnce(null) // not found by real publicKey
        .mockResolvedValueOnce(placeholderUser); // found by placeholder
      userRepository.save.mockResolvedValue({
        ...placeholderUser,
        publicKey: 'real-public-key',
      });

      const mockAuthMethod = { id: 'am-1', userId: 'user-id', type: 'email_passwordless' };
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.login(corekitLoginDto);

      expect(result.isNewUser).toBe(false);
      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ publicKey: 'real-public-key' })
      );
    });

    it('should find existing auth method by identifier for corekit login (no duplicates)', async () => {
      const corekitLoginDto = {
        idToken: 'cipherbox-jwt',
        publicKey: 'abc123',
        loginType: 'corekit' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: 'test@example.com' },
      });

      const mockUser = { id: 'user-id', publicKey: 'abc123', derivationVersion: null };
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

      await service.login(corekitLoginDto);

      // Should NOT call web3AuthVerifier methods for corekit login
      expect(web3AuthVerifier.extractAuthMethodType).not.toHaveBeenCalled();
      expect(web3AuthVerifier.extractIdentifier).not.toHaveBeenCalled();

      // Should look up by userId + identifier, not hardcode type
      expect(authMethodRepository.findOne).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: 'user-id', identifier: 'test@example.com' },
        })
      );
    });

    it('should backfill auth method identifier when email differs', async () => {
      const mockPayload = { verifier: 'google', email: 'real-email@example.com' };
      const mockUser = { id: 'user-id', publicKey: 'abc123', derivationVersion: null };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'user-id',
        type: 'google',
        identifier: 'old-uuid-identifier',
        lastUsedAt: null,
      };
      const mockTokens = { accessToken: 'at', refreshToken: 'rt' };

      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('google');
      web3AuthVerifier.extractIdentifier.mockReturnValue('real-email@example.com');
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue(mockTokens);

      await service.login(loginDto);

      expect(mockAuthMethod.identifier).toBe('real-email@example.com');
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
        where: { userId: 'user-id', type: 'email_passwordless' },
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
          lastUsedAt: new Date(),
          createdAt: new Date('2024-01-01'),
        },
        {
          id: 'am-2',
          type: 'github',
          identifier: 'user123',
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
      expect(result[1].type).toBe('github');
    });

    it('should return empty array if no methods', async () => {
      authMethodRepository.find.mockResolvedValue([]);

      const result = await service.getLinkedMethods('user-id');

      expect(result).toEqual([]);
    });
  });

  describe('linkMethod', () => {
    const linkDto = {
      idToken: 'new-token',
      loginType: 'social' as const,
    };

    it('should verify token and create new auth method', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { verifier: 'github', verifierId: 'gh-user' };
      const mockMethod = {
        id: 'new-am',
        type: 'github',
        identifier: 'gh-user',
        lastUsedAt: new Date(),
        createdAt: new Date(),
      };

      userRepository.findOne.mockResolvedValue(mockUser);
      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('github');
      web3AuthVerifier.extractIdentifier.mockReturnValue('gh-user');
      authMethodRepository.findOne.mockResolvedValue(null);
      authMethodRepository.save.mockResolvedValue(mockMethod);
      authMethodRepository.find.mockResolvedValue([mockMethod]);

      const result = await service.linkMethod('user-id', linkDto);

      expect(web3AuthVerifier.verifyIdToken).toHaveBeenCalledWith('new-token', 'pub-key', 'social');
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'github',
          identifier: 'gh-user',
        })
      );
      expect(result).toHaveLength(1);
    });

    it('should throw BadRequestException if method already linked', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { verifier: 'github', verifierId: 'gh-user' };
      const existingMethod = { id: 'existing', type: 'github', identifier: 'gh-user' };

      userRepository.findOne.mockResolvedValue(mockUser);
      web3AuthVerifier.verifyIdToken.mockResolvedValue(mockPayload);
      web3AuthVerifier.extractAuthMethodType.mockReturnValue('github');
      web3AuthVerifier.extractIdentifier.mockReturnValue('gh-user');
      authMethodRepository.findOne.mockResolvedValue(existingMethod);

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(BadRequestException);
      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(
        'This auth method is already linked to your account'
      );
    });

    it('should throw UnauthorizedException if user not found', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(UnauthorizedException);
      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow('User not found');
    });
  });

  describe('unlinkMethod', () => {
    it('should remove auth method', async () => {
      const mockMethod = { id: 'method-id', userId: 'user-id', type: 'github' };

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
        type: 'email_passwordless',
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
          type: 'email_passwordless',
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
        type: 'email_passwordless',
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
