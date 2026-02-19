import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';
import { User } from '../entities/user.entity';

describe('JwtStrategy', () => {
  describe('constructor', () => {
    it('should throw Error if JWT_SECRET is not configured', async () => {
      await expect(
        Test.createTestingModule({
          providers: [
            JwtStrategy,
            {
              provide: ConfigService,
              useValue: { get: jest.fn(() => undefined) },
            },
            {
              provide: getRepositoryToken(User),
              useValue: {},
            },
          ],
        }).compile()
      ).rejects.toThrow('JWT_SECRET environment variable is not set');
    });

    it('should initialize successfully with valid JWT_SECRET', async () => {
      const module = await Test.createTestingModule({
        providers: [
          JwtStrategy,
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn((key: string) => {
                if (key === 'JWT_SECRET') return 'test-secret-key-for-jwt';
                return undefined;
              }),
            },
          },
          {
            provide: getRepositoryToken(User),
            useValue: {
              findOne: jest.fn(),
            },
          },
        ],
      }).compile();

      const strategy = module.get<JwtStrategy>(JwtStrategy);
      expect(strategy).toBeDefined();
    });
  });

  describe('validate', () => {
    let strategy: JwtStrategy;
    let userRepository: jest.Mocked<Record<string, jest.Mock>>;

    beforeEach(async () => {
      const mockUserRepo = {
        findOne: jest.fn(),
      };

      const module: TestingModule = await Test.createTestingModule({
        providers: [
          JwtStrategy,
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn((key: string) => {
                if (key === 'JWT_SECRET') return 'test-secret-key-for-jwt';
                return undefined;
              }),
            },
          },
          {
            provide: getRepositoryToken(User),
            useValue: mockUserRepo,
          },
        ],
      }).compile();

      strategy = module.get<JwtStrategy>(JwtStrategy);
      userRepository = module.get(getRepositoryToken(User));
    });

    afterEach(() => {
      jest.resetAllMocks();
    });

    it('should return user if found by payload.sub', async () => {
      const mockUser = {
        id: 'user-uuid-123',
        publicKey: 'pubkey123',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      userRepository.findOne.mockResolvedValue(mockUser);

      const payload = {
        sub: 'user-uuid-123',
        publicKey: 'pubkey123',
        iat: 1234567890,
        exp: 1234567890 + 900,
      };

      const result = await strategy.validate(payload);

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'user-uuid-123' },
      });
      expect(result).toEqual(mockUser);
    });

    it('should throw UnauthorizedException if user not found', async () => {
      userRepository.findOne.mockResolvedValue(null);

      const payload = {
        sub: 'non-existent-user',
        publicKey: 'pubkey123',
        iat: 1234567890,
        exp: 1234567890 + 900,
      };

      await expect(strategy.validate(payload)).rejects.toThrow(UnauthorizedException);
      await expect(strategy.validate(payload)).rejects.toThrow('User not found');
    });
  });
});
