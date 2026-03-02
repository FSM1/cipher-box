import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UnauthorizedException, BadRequestException } from '@nestjs/common';
import { createHash } from 'crypto';
import * as jose from 'jose';
import { AuthMethodService } from './auth-method.service';
import { JwtIssuerService } from './jwt-issuer.service';
import { SiweService } from './siwe.service';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';
import { REDIS_CLIENT } from '../../common/redis.module';

const mockRedisInstance = {
  del: jest.fn().mockResolvedValue(1),
  set: jest.fn().mockResolvedValue('OK'),
  quit: jest.fn().mockResolvedValue('OK'),
};

/** Helper: compute expected SHA-256 hex hash */
function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

describe('AuthMethodService', () => {
  let service: AuthMethodService;
  let jwtIssuerService: Record<string, jest.Mock>;
  let siweService: Record<string, jest.Mock>;
  let userRepository: Record<string, jest.Mock>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let authMethodRepository: Record<string, any>;

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
      manager: {
        transaction: jest.fn((cb: (manager: unknown) => Promise<unknown>) => {
          const mockManager = {
            createQueryBuilder: jest.fn().mockReturnValue({
              setLock: jest.fn().mockReturnThis(),
              where: jest.fn().mockReturnThis(),
              getMany: jest.fn(),
            }),
            remove: jest.fn(),
          };
          return cb(mockManager);
        }),
      },
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
        AuthMethodService,
        { provide: JwtIssuerService, useValue: mockJwtIssuerService },
        { provide: SiweService, useValue: mockSiweService },
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: getRepositoryToken(AuthMethod), useValue: mockAuthMethodRepo },
        { provide: REDIS_CLIENT, useValue: mockRedisInstance },
      ],
    }).compile();

    service = module.get<AuthMethodService>(AuthMethodService);
    jwtIssuerService = module.get(JwtIssuerService);
    siweService = module.get(SiweService);
    userRepository = module.get(getRepositoryToken(User));
    authMethodRepository = module.get(getRepositoryToken(AuthMethod));
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockRedisInstance.del.mockResolvedValue(1);
    mockRedisInstance.set.mockResolvedValue('OK');
    mockRedisInstance.quit.mockResolvedValue('OK');
  });

  describe('getLinkedMethods', () => {
    it('should return identifierDisplay for all auth method types', async () => {
      const mockMethods = [
        {
          id: 'am-1',
          type: 'google',
          identifier: sha256Hex('google-sub-123'),
          identifierDisplay: 'user@gmail.com',
          lastUsedAt: new Date(),
          createdAt: new Date('2024-01-01'),
        },
        {
          id: 'am-2',
          type: 'email',
          identifier: sha256Hex('user@example.com'),
          identifierDisplay: 'user@example.com',
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
      expect(result[0].identifier).toBe('user@gmail.com');
      expect(result[1].identifier).toBe('user@example.com');
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

    it('should fall back to [redacted] when identifierDisplay is null', async () => {
      const mockMethods = [
        {
          id: 'am-1',
          type: 'google',
          identifier: 'legacy-plaintext-email',
          identifierDisplay: null,
          lastUsedAt: new Date(),
          createdAt: new Date('2024-01-01'),
        },
      ];

      authMethodRepository.find.mockResolvedValue(mockMethods);

      const result = await service.getLinkedMethods('user-id');

      expect(result[0].identifier).toBe('[redacted]');
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

    it('should verify CipherBox JWT and create new auth method with identifierHash', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };
      const identifierHash = sha256Hex('user@example.com');
      const mockMethod = {
        id: 'new-am',
        type: 'google',
        identifier: identifierHash,
        identifierDisplay: 'user@example.com',
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
          identifier: identifierHash,
          identifierHash,
          identifierDisplay: 'user@example.com',
        })
      );
      expect(result).toHaveLength(1);
    });

    it('should use identifierHash for duplicate check', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };
      const identifierHash = sha256Hex('user@example.com');
      const existingMethod = {
        id: 'existing',
        type: 'google',
        identifierHash,
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      userRepository.findOne.mockResolvedValue(mockUser);
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // cross-account
        .mockResolvedValueOnce(existingMethod); // same-user duplicate

      await expect(service.linkMethod('user-id', linkDto)).rejects.toThrow(BadRequestException);
    });

    it('should use identifierHash for cross-account collision check', async () => {
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };
      const mockPayload = { sub: 'user-123', email: 'user@example.com' };
      const identifierHash = sha256Hex('user@example.com');
      const otherAccountMethod = {
        id: 'other-am',
        type: 'google',
        identifierHash,
        userId: 'other-user-id',
      };

      jwtIssuerService.getJwksData.mockReturnValue({ keys: [] });
      (jose.createLocalJWKSet as jest.Mock).mockReturnValue('mock-jwks');
      (jose.jwtVerify as jest.Mock).mockResolvedValue({ payload: mockPayload });

      userRepository.findOne.mockResolvedValue(mockUser);
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
        identifierHash: sha256Hex('user@example.com'),
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
        identifierHash: sha256Hex('user@example.com'),
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
      authMethodRepository.findOne.mockResolvedValue(null);
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
      authMethodRepository.findOne.mockResolvedValueOnce({
        id: 'other-am',
        userId: 'other-user-id',
      });

      await expect(service.linkMethod('user-id', walletLinkDto)).rejects.toThrow(
        BadRequestException
      );
    });

    it('should throw BadRequestException when SIWE message has no nonce', async () => {
      const siweMsg = [
        'localhost wants you to sign in with your Ethereum account:',
        '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12',
        '',
        'Sign in to CipherBox encrypted storage',
        '',
        'URI: http://localhost:5173',
        'Version: 1',
        'Chain ID: 1',
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

      await expect(service.linkMethod('user-id', walletLinkDto)).rejects.toThrow('missing nonce');
    });

    it('should throw BadRequestException when wallet already linked to same user', async () => {
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
      // No cross-account collision, but same-user duplicate
      authMethodRepository.findOne
        .mockResolvedValueOnce(null) // cross-account check
        .mockResolvedValueOnce({ id: 'existing-am', userId: 'user-id' }); // same-user check

      await expect(service.linkMethod('user-id', walletLinkDto)).rejects.toThrow(
        'already linked to your account'
      );
    });

    it('should throw BadRequestException when wallet SIWE fields missing', async () => {
      const walletLinkDto = {
        idToken: '',
        loginType: 'wallet' as const,
      };
      const mockUser = { id: 'user-id', publicKey: 'pub-key' };

      userRepository.findOne.mockResolvedValue(mockUser);

      await expect(service.linkMethod('user-id', walletLinkDto)).rejects.toThrow(
        BadRequestException
      );
    });
  });

  describe('unlinkMethod', () => {
    function setupTransactionMock(methods: Array<{ id: string }>) {
      authMethodRepository.manager.transaction.mockImplementation(
        async (cb: (manager: Record<string, jest.Mock>) => Promise<void>) => {
          const mockManager = {
            createQueryBuilder: jest.fn().mockReturnValue({
              setLock: jest.fn().mockReturnThis(),
              where: jest.fn().mockReturnThis(),
              getMany: jest.fn().mockResolvedValue(methods),
            }),
            remove: jest.fn(),
          };
          return cb(mockManager);
        }
      );
    }

    it('should remove auth method within transaction', async () => {
      const mockMethod = { id: 'method-id', userId: 'user-id', type: 'google' };
      const otherMethod = { id: 'other-id', userId: 'user-id', type: 'email' };

      setupTransactionMock([mockMethod, otherMethod]);

      await service.unlinkMethod('user-id', 'method-id');

      expect(authMethodRepository.manager.transaction).toHaveBeenCalled();
    });

    it('should throw BadRequestException if method not found', async () => {
      setupTransactionMock([{ id: 'other-id' }]);

      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        BadRequestException
      );
      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        'Auth method not found'
      );
    });

    it('should throw BadRequestException if last auth method', async () => {
      setupTransactionMock([{ id: 'method-id' }]);

      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        BadRequestException
      );
      await expect(service.unlinkMethod('user-id', 'method-id')).rejects.toThrow(
        'Cannot unlink your last auth method'
      );
    });
  });
});
