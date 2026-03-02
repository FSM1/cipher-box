import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UnauthorizedException, BadRequestException } from '@nestjs/common';
import { createHash } from 'crypto';
import * as argon2 from 'argon2';
import * as jose from 'jose';
import { AuthService } from './auth.service';
import { JwtIssuerService } from './services/jwt-issuer.service';
import { TokenService } from './services/token.service';
import { SiweService } from './services/siwe.service';
import { User } from './entities/user.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { IPFS_PROVIDER } from '../ipfs/providers/ipfs-provider.interface';

/** Helper: compute expected SHA-256 hex hash */
function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

describe('AuthService', () => {
  let service: AuthService;
  let jwtIssuerService: Record<string, jest.Mock>;
  let tokenService: jest.Mocked<TokenService>;
  let userRepository: Record<string, jest.Mock>;
  let authMethodRepository: Record<string, jest.Mock>;
  let refreshTokenRepository: Record<string, jest.Mock>;
  let pinnedCidRepository: Record<string, jest.Mock>;
  let ipfsProvider: Record<string, jest.Mock>;

  beforeEach(async () => {
    const mockUserRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
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

    const mockPinnedCidRepo = {
      find: jest.fn(),
    };

    const mockIpfsProvider = {
      unpinFile: jest.fn().mockResolvedValue(undefined),
    };

    const mockTokenService = {
      createTokens: jest.fn(),
      rotateRefreshToken: jest.fn(),
      revokeAllUserTokens: jest.fn(),
    };

    const mockJwtIssuerService = {
      getJwksData: jest.fn(),
      signIdentityJwt: jest.fn(),
    };

    const mockSiweService = {
      generateNonce: jest.fn(),
      verifySiweMessage: jest.fn(),
      hashWalletAddress: jest.fn(),
      hashIdentifier: jest.fn((value: string) => createHash('sha256').update(value).digest('hex')),
      truncateWalletAddress: jest.fn((addr: string) => `${addr.slice(0, 6)}...${addr.slice(-4)}`),
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
        AuthService,
        { provide: JwtIssuerService, useValue: mockJwtIssuerService },
        { provide: TokenService, useValue: mockTokenService },
        { provide: SiweService, useValue: mockSiweService },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: getRepositoryToken(AuthMethod), useValue: mockAuthMethodRepo },
        { provide: getRepositoryToken(RefreshToken), useValue: mockRefreshTokenRepo },
        { provide: getRepositoryToken(PinnedCid), useValue: mockPinnedCidRepo },
        { provide: IPFS_PROVIDER, useValue: mockIpfsProvider },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jwtIssuerService = module.get(JwtIssuerService);
    tokenService = module.get(TokenService);
    userRepository = module.get(getRepositoryToken(User));
    authMethodRepository = module.get(getRepositoryToken(AuthMethod));
    refreshTokenRepository = module.get(getRepositoryToken(RefreshToken));
    pinnedCidRepository = module.get(getRepositoryToken(PinnedCid));
    ipfsProvider = module.get(IPFS_PROVIDER);
  });

  afterEach(() => {
    jest.clearAllMocks();
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
        .mockResolvedValueOnce(null) // identifierHash lookup
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
      const identifierHash = sha256Hex('test@example.com');
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'existing-id',
        type: 'google',
        identifier: identifierHash,
        identifierHash,
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
        identifier: sha256Hex('test@example.com'),
        identifierHash: sha256Hex('test@example.com'),
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

    it('should look up auth method by identifierHash (not plaintext identifier)', async () => {
      const mockPayload = { sub: 'user-123', email: 'test@example.com' };
      const identifierHash = sha256Hex('test@example.com');

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      const mockAuthMethod = {
        id: 'am-1',
        userId: 'user-id',
        type: 'google',
        identifier: identifierHash,
        identifierHash,
        lastUsedAt: null,
      };
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      // Should look up by userId + identifierHash, not plaintext identifier
      expect(authMethodRepository.findOne).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: 'user-id', identifierHash },
        })
      );
    });

    it('should fall back to any auth method when identifierHash not found', async () => {
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
        identifier: 'different-hash',
        lastUsedAt: null,
      };
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifierHash lookup - no match
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

    it('should create safety net auth method with identifierHash and identifierDisplay', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: 'test@example.com' },
      });

      const identifierHash = sha256Hex('test@example.com');
      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifierHash lookup
        .mockResolvedValueOnce(null); // userId fallback
      const savedMethod = {
        id: 'am-new',
        userId: 'user-id',
        type: 'email',
        identifier: identifierHash,
        identifierHash,
        identifierDisplay: 'test@example.com',
        lastUsedAt: null,
      };
      authMethodRepository.save.mockResolvedValue(savedMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      // Safety net should store hashed identifier + display
      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'email',
          identifier: identifierHash,
          identifierHash,
          identifierDisplay: 'test@example.com',
        })
      );
    });

    it('should infer wallet type in safety net when identifier starts with 0x', async () => {
      const walletAddr = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
      const identifierHash = sha256Hex(walletAddr);
      const truncatedAddr = `${walletAddr.slice(0, 6)}...${walletAddr.slice(-4)}`;

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: walletAddr },
      });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // identifierHash lookup
        .mockResolvedValueOnce(null); // userId fallback
      const savedMethod = {
        id: 'am-wallet',
        userId: 'user-id',
        type: 'wallet',
        identifier: identifierHash,
        identifierHash,
        identifierDisplay: truncatedAddr,
        lastUsedAt: null,
      };
      authMethodRepository.save.mockResolvedValue(savedMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      await service.login(loginDto);

      expect(authMethodRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          type: 'wallet',
          identifier: identifierHash,
          identifierHash,
          identifierDisplay: truncatedAddr,
        })
      );
    });

    it('should throw UnauthorizedException when JWT has no email or sub', async () => {
      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: {},
      });

      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.findOne.mockResolvedValue(mockUser);

      await expect(service.login(loginDto)).rejects.toThrow(UnauthorizedException);
      await expect(service.login(loginDto)).rejects.toThrow('missing identifier');
    });

    it('should skip placeholder resolution when no verifierId or sub', async () => {
      const mockPayload = { email: 'test@example.com' }; // no sub, no verifierId

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      userRepository.findOne.mockResolvedValue(null);
      const mockUser = { id: 'user-id', publicKey: 'abc123' };
      userRepository.save.mockResolvedValue(mockUser);
      authMethodRepository.findOne.mockResolvedValueOnce(null).mockResolvedValueOnce(null);
      authMethodRepository.save.mockResolvedValue({
        id: 'am-new',
        userId: 'user-id',
        type: 'email',
        identifier: sha256Hex('test@example.com'),
        identifierHash: sha256Hex('test@example.com'),
        identifierDisplay: 'test@example.com',
        lastUsedAt: null,
      });
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.login(loginDto);

      expect(result.isNewUser).toBe(true);
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
        publicKey: 'pending-core-kit-user-123',
      };
      userRepository.findOne
        .mockResolvedValueOnce(null) // not found by real publicKey
        .mockResolvedValueOnce(placeholderUser); // found by exact placeholder match
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

    it('should not overwrite publicKey when placeholder login finds placeholder user', async () => {
      const placeholderLoginDto = {
        idToken: 'cipherbox-jwt',
        publicKey: 'pending-core-kit-user-123',
        loginType: 'corekit' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-123', email: 'test@example.com' },
      });

      const placeholderUser = {
        id: 'user-id',
        publicKey: 'pending-core-kit-user-123',
      };
      userRepository.findOne
        .mockResolvedValueOnce(null) // not found by placeholder publicKey
        .mockResolvedValueOnce(placeholderUser); // found by exact placeholder match
      // save should NOT be called for publicKey update (incoming is also a placeholder)

      const mockAuthMethod = { id: 'am-1', userId: 'user-id', type: 'email' };
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.login(placeholderLoginDto);

      expect(result.isNewUser).toBe(false);
      // Should NOT have called userRepository.save (no publicKey update)
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should find existing user by userId for REQUIRED_SHARE temp auth', async () => {
      const requiredShareDto = {
        idToken: 'cipherbox-jwt',
        publicKey: 'pending-core-kit-existing-user-id',
        loginType: 'corekit' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'existing-user-id', email: 'test@example.com' },
      });

      const existingUser = {
        id: 'existing-user-id',
        publicKey: '04' + 'a'.repeat(128), // real Core Kit key
      };

      userRepository.findOne
        .mockResolvedValueOnce(null) // not found by placeholder publicKey
        .mockResolvedValueOnce(null) // not found by exact placeholder match
        .mockResolvedValueOnce(existingUser); // found by userId lookup

      const mockAuthMethod = { id: 'am-1', userId: 'existing-user-id', type: 'email' };
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.login(requiredShareDto);

      expect(result.isNewUser).toBe(false);
      // Verify userId-based lookup was called
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'existing-user-id' },
      });
      expect(result.accessToken).toBe('at');
    });

    it('should issue scoped tokens for REQUIRED_SHARE temp auth', async () => {
      const requiredShareDto = {
        idToken: 'cipherbox-jwt',
        publicKey: 'pending-core-kit-existing-user-id',
        loginType: 'corekit' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'existing-user-id', email: 'test@example.com' },
      });

      const existingUser = {
        id: 'existing-user-id',
        publicKey: '04' + 'a'.repeat(128),
      };

      userRepository.findOne
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(existingUser);

      const mockAuthMethod = { id: 'am-1', userId: 'existing-user-id', type: 'email' };
      authMethodRepository.findOne.mockResolvedValue(mockAuthMethod);
      authMethodRepository.save.mockResolvedValue(mockAuthMethod);
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: '' });

      await service.login(requiredShareDto);

      // Verify scoped tokens are issued for REQUIRED_SHARE temp auth
      expect(tokenService.createTokens).toHaveBeenCalledWith(
        'existing-user-id',
        '04' + 'a'.repeat(128),
        { scope: ['device-approval'], skipRefreshToken: true }
      );
    });

    it('should create new user when REQUIRED_SHARE has no existing user', async () => {
      const requiredShareDto = {
        idToken: 'cipherbox-jwt',
        publicKey: 'pending-core-kit-user-456',
        loginType: 'corekit' as const,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'user-456', email: 'new@example.com' },
      });

      userRepository.findOne
        .mockResolvedValueOnce(null) // not found by placeholder publicKey
        .mockResolvedValueOnce(null) // not found by exact placeholder match
        .mockResolvedValueOnce(null); // not found by userId lookup

      authMethodRepository.findOne.mockResolvedValue(null);

      const newUser = { id: 'new-user-id', publicKey: 'pending-core-kit-user-456' };
      userRepository.save.mockResolvedValue(newUser);
      const mockAuthMethod = { id: 'am-new', userId: 'new-user-id', type: 'email' };
      authMethodRepository.save
        .mockResolvedValueOnce(mockAuthMethod) // safety net create
        .mockResolvedValueOnce(mockAuthMethod); // lastUsedAt update
      tokenService.createTokens.mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.login(requiredShareDto);

      expect(result.isNewUser).toBe(true);
      expect(userRepository.save).toHaveBeenCalledWith({
        publicKey: 'pending-core-kit-user-456',
      });
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

    it('should return identifierDisplay as email (not hashed identifier)', async () => {
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
      authMethodRepository.findOne.mockResolvedValue({
        identifier: sha256Hex('test@example.com'),
        identifierDisplay: 'test@example.com',
      });

      const result = await service.refreshByToken(refreshToken);

      // Should return identifierDisplay (human-readable), not the hash
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

  // getLinkedMethods, linkMethod, unlinkMethod tests moved to auth-method.service.spec.ts
  // testLogin tests moved to test-auth.service.spec.ts

  describe('deleteAccount', () => {
    const userId = 'user-to-delete';

    it('should unpin all CIDs and delete user', async () => {
      pinnedCidRepository.find.mockResolvedValue([{ cid: 'QmCid1' }, { cid: 'QmCid2' }]);
      userRepository.delete.mockResolvedValue({ affected: 1 });

      const result = await service.deleteAccount(userId);

      expect(pinnedCidRepository.find).toHaveBeenCalledWith({
        where: { userId },
        select: ['cid'],
      });
      expect(ipfsProvider.unpinFile).toHaveBeenCalledTimes(2);
      expect(ipfsProvider.unpinFile).toHaveBeenCalledWith('QmCid1');
      expect(ipfsProvider.unpinFile).toHaveBeenCalledWith('QmCid2');
      expect(userRepository.delete).toHaveBeenCalledWith(userId);
      expect(result).toEqual({ success: true });
    });

    it('should skip unpinning when no pinned CIDs exist', async () => {
      pinnedCidRepository.find.mockResolvedValue([]);
      userRepository.delete.mockResolvedValue({ affected: 1 });

      const result = await service.deleteAccount(userId);

      expect(ipfsProvider.unpinFile).not.toHaveBeenCalled();
      expect(userRepository.delete).toHaveBeenCalledWith(userId);
      expect(result).toEqual({ success: true });
    });

    it('should still delete user when some unpins fail', async () => {
      pinnedCidRepository.find.mockResolvedValue([{ cid: 'QmGood' }, { cid: 'QmBad' }]);
      ipfsProvider.unpinFile
        .mockResolvedValueOnce(undefined)
        .mockRejectedValueOnce(new Error('unpin failed'));
      userRepository.delete.mockResolvedValue({ affected: 1 });

      const result = await service.deleteAccount(userId);

      expect(ipfsProvider.unpinFile).toHaveBeenCalledTimes(2);
      expect(ipfsProvider.unpinFile).toHaveBeenCalledWith('QmGood');
      expect(ipfsProvider.unpinFile).toHaveBeenCalledWith('QmBad');
      expect(userRepository.delete).toHaveBeenCalledWith(userId);
      expect(result).toEqual({ success: true });
    });

    it('should throw BadRequestException when user not found', async () => {
      pinnedCidRepository.find.mockResolvedValue([]);
      userRepository.delete.mockResolvedValue({ affected: 0 });

      await expect(service.deleteAccount(userId)).rejects.toThrow(BadRequestException);
      await expect(service.deleteAccount(userId)).rejects.toThrow('Account not found');
    });
  });
});
