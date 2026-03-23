"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const testing_1 = require("@nestjs/testing");
const typeorm_1 = require("@nestjs/typeorm");
const config_1 = require("@nestjs/config");
const common_1 = require("@nestjs/common");
const jwt_strategy_1 = require("./jwt.strategy");
const user_entity_1 = require("../entities/user.entity");
describe('JwtStrategy', () => {
    describe('constructor', () => {
        it('should throw Error if JWT_SECRET is not configured', async () => {
            await expect(testing_1.Test.createTestingModule({
                providers: [
                    jwt_strategy_1.JwtStrategy,
                    {
                        provide: config_1.ConfigService,
                        useValue: { get: jest.fn(() => undefined) },
                    },
                    {
                        provide: (0, typeorm_1.getRepositoryToken)(user_entity_1.User),
                        useValue: {},
                    },
                ],
            }).compile()).rejects.toThrow('JWT_SECRET environment variable is not set');
        });
        it('should initialize successfully with valid JWT_SECRET', async () => {
            const module = await testing_1.Test.createTestingModule({
                providers: [
                    jwt_strategy_1.JwtStrategy,
                    {
                        provide: config_1.ConfigService,
                        useValue: {
                            get: jest.fn((key) => {
                                if (key === 'JWT_SECRET')
                                    return 'test-secret-key-for-jwt';
                                return undefined;
                            }),
                        },
                    },
                    {
                        provide: (0, typeorm_1.getRepositoryToken)(user_entity_1.User),
                        useValue: {
                            findOne: jest.fn(),
                        },
                    },
                ],
            }).compile();
            const strategy = module.get(jwt_strategy_1.JwtStrategy);
            expect(strategy).toBeDefined();
        });
    });
    describe('validate', () => {
        let strategy;
        let userRepository;
        beforeEach(async () => {
            const mockUserRepo = {
                findOne: jest.fn(),
            };
            const module = await testing_1.Test.createTestingModule({
                providers: [
                    jwt_strategy_1.JwtStrategy,
                    {
                        provide: config_1.ConfigService,
                        useValue: {
                            get: jest.fn((key) => {
                                if (key === 'JWT_SECRET')
                                    return 'test-secret-key-for-jwt';
                                return undefined;
                            }),
                        },
                    },
                    {
                        provide: (0, typeorm_1.getRepositoryToken)(user_entity_1.User),
                        useValue: mockUserRepo,
                    },
                ],
            }).compile();
            strategy = module.get(jwt_strategy_1.JwtStrategy);
            userRepository = module.get((0, typeorm_1.getRepositoryToken)(user_entity_1.User));
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
            await expect(strategy.validate(payload)).rejects.toThrow(common_1.UnauthorizedException);
            await expect(strategy.validate(payload)).rejects.toThrow('User not found');
        });
    });
});
//# sourceMappingURL=jwt.strategy.spec.js.map