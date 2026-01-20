import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import * as argon2 from 'argon2';
import { TokenService } from './token.service';
import { RefreshToken } from '../entities/refresh-token.entity';

describe('TokenService', () => {
  let service: TokenService;
  let jwtService: jest.Mocked<JwtService>;
  let refreshTokenRepo: jest.Mocked<Record<string, jest.Mock>>;

  beforeEach(async () => {
    const mockJwtService = {
      sign: jest.fn().mockReturnValue('mock-jwt-access-token'),
    };

    const mockRefreshTokenRepo = {
      find: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TokenService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: getRepositoryToken(RefreshToken), useValue: mockRefreshTokenRepo },
      ],
    }).compile();

    service = module.get<TokenService>(TokenService);
    jwtService = module.get(JwtService);
    refreshTokenRepo = module.get(getRepositoryToken(RefreshToken));
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('createTokens', () => {
    it('should generate access token with correct payload', async () => {
      refreshTokenRepo.save.mockResolvedValue({
        id: 'token-id',
        userId: 'user-123',
        tokenHash: 'hashed',
        expiresAt: new Date(),
      });

      await service.createTokens('user-123', 'public-key-abc');

      expect(jwtService.sign).toHaveBeenCalledWith(
        { sub: 'user-123', publicKey: 'public-key-abc' },
        { expiresIn: '15m' }
      );
    });

    it('should generate random refresh token and hash with argon2', async () => {
      refreshTokenRepo.save.mockResolvedValue({
        id: 'token-id',
        userId: 'user-123',
        tokenHash: 'hashed',
        expiresAt: new Date(),
      });

      const result = await service.createTokens('user-123', 'public-key');

      // Verify refresh token is hex-encoded (32 bytes = 64 hex chars)
      expect(result.refreshToken).toMatch(/^[a-f0-9]{64}$/);

      // Verify save was called with a hashed token (argon2 format)
      expect(refreshTokenRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenHash: expect.stringMatching(/^\$argon2/),
        })
      );
    });

    it('should save hashed token to database with correct expiry (7 days)', async () => {
      const beforeTest = new Date();
      refreshTokenRepo.save.mockResolvedValue({
        id: 'token-id',
        userId: 'user-123',
        tokenHash: 'hashed',
        expiresAt: new Date(),
      });

      await service.createTokens('user-123', 'public-key');

      const saveCall = refreshTokenRepo.save.mock.calls[0][0];
      const expiresAt = saveCall.expiresAt as Date;

      // Should be approximately 7 days from now
      const expectedExpiry = new Date(beforeTest.getTime() + 7 * 24 * 60 * 60 * 1000);
      expect(expiresAt.getTime()).toBeGreaterThanOrEqual(expectedExpiry.getTime() - 1000);
      expect(expiresAt.getTime()).toBeLessThanOrEqual(expectedExpiry.getTime() + 1000);

      expect(saveCall.userId).toBe('user-123');
    });

    it('should return both tokens', async () => {
      refreshTokenRepo.save.mockResolvedValue({
        id: 'token-id',
        userId: 'user-123',
        tokenHash: 'hashed',
        expiresAt: new Date(),
      });

      const result = await service.createTokens('user-123', 'public-key');

      expect(result.accessToken).toBe('mock-jwt-access-token');
      expect(result.refreshToken).toBeDefined();
      expect(typeof result.refreshToken).toBe('string');
    });
  });

  describe('rotateRefreshToken', () => {
    it('should find non-revoked tokens for user', async () => {
      const refreshToken = 'valid-token';
      const tokenHash = await argon2.hash(refreshToken);
      const mockToken = {
        id: 'token-id',
        userId: 'user-123',
        tokenHash,
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
      };

      refreshTokenRepo.find.mockResolvedValue([mockToken]);
      refreshTokenRepo.save.mockResolvedValue({ ...mockToken, revokedAt: new Date() });

      await service.rotateRefreshToken(refreshToken, 'user-123', 'public-key');

      expect(refreshTokenRepo.find).toHaveBeenCalledWith({
        where: {
          userId: 'user-123',
          revokedAt: expect.anything(), // IsNull()
        },
      });
    });

    it('should verify token against argon2 hashes', async () => {
      const refreshToken = 'valid-token';
      const tokenHash = await argon2.hash(refreshToken);
      const mockToken = {
        id: 'token-id',
        userId: 'user-123',
        tokenHash,
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
      };

      refreshTokenRepo.find.mockResolvedValue([mockToken]);
      refreshTokenRepo.save.mockResolvedValue({ ...mockToken, revokedAt: new Date() });

      const result = await service.rotateRefreshToken(refreshToken, 'user-123', 'public-key');

      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('should throw UnauthorizedException if no match', async () => {
      refreshTokenRepo.find.mockResolvedValue([]);

      await expect(
        service.rotateRefreshToken('invalid-token', 'user-123', 'public-key')
      ).rejects.toThrow(UnauthorizedException);

      await expect(
        service.rotateRefreshToken('invalid-token', 'user-123', 'public-key')
      ).rejects.toThrow('Invalid refresh token');
    });

    it('should throw UnauthorizedException if token expired (and revoke it)', async () => {
      const refreshToken = 'expired-token';
      const tokenHash = await argon2.hash(refreshToken);
      const expiredToken = {
        id: 'token-id',
        userId: 'user-123',
        tokenHash,
        expiresAt: new Date(Date.now() - 86400000), // Expired yesterday
        revokedAt: null,
      };

      refreshTokenRepo.find.mockResolvedValue([expiredToken]);
      refreshTokenRepo.save.mockResolvedValue({ ...expiredToken, revokedAt: new Date() });

      await expect(
        service.rotateRefreshToken(refreshToken, 'user-123', 'public-key')
      ).rejects.toThrow(UnauthorizedException);

      await expect(
        service.rotateRefreshToken(refreshToken, 'user-123', 'public-key')
      ).rejects.toThrow('Refresh token expired');

      // Verify token was revoked
      expect(refreshTokenRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          revokedAt: expect.any(Date),
        })
      );
    });

    it('should revoke old token and create new tokens', async () => {
      const refreshToken = 'valid-token';
      const tokenHash = await argon2.hash(refreshToken);
      const mockToken = {
        id: 'token-id',
        userId: 'user-123',
        tokenHash,
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
      };

      refreshTokenRepo.find.mockResolvedValue([mockToken]);
      refreshTokenRepo.save
        .mockResolvedValueOnce({ ...mockToken, revokedAt: new Date() }) // Revoke old
        .mockResolvedValueOnce({ id: 'new-token-id' }); // Save new

      const result = await service.rotateRefreshToken(refreshToken, 'user-123', 'public-key');

      // First save call should revoke old token
      expect(refreshTokenRepo.save.mock.calls[0][0]).toEqual(
        expect.objectContaining({
          revokedAt: expect.any(Date),
        })
      );

      // Should create new tokens
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('should handle argon2.verify exceptions gracefully', async () => {
      const mockToken = {
        id: 'token-id',
        userId: 'user-123',
        tokenHash: 'invalid-hash-format', // Not a valid argon2 hash
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
      };

      refreshTokenRepo.find.mockResolvedValue([mockToken]);

      await expect(
        service.rotateRefreshToken('some-token', 'user-123', 'public-key')
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('revokeAllUserTokens', () => {
    it('should update all non-revoked tokens for user with revokedAt', async () => {
      refreshTokenRepo.update.mockResolvedValue({ affected: 3 });

      await service.revokeAllUserTokens('user-123');

      expect(refreshTokenRepo.update).toHaveBeenCalledWith(
        { userId: 'user-123', revokedAt: expect.anything() }, // IsNull()
        { revokedAt: expect.any(Date) }
      );
    });
  });

  describe('revokeToken', () => {
    it('should update specific token with revokedAt', async () => {
      refreshTokenRepo.update.mockResolvedValue({ affected: 1 });

      await service.revokeToken('token-uuid');

      expect(refreshTokenRepo.update).toHaveBeenCalledWith(
        { id: 'token-uuid', revokedAt: expect.anything() }, // IsNull()
        { revokedAt: expect.any(Date) }
      );
    });
  });
});
