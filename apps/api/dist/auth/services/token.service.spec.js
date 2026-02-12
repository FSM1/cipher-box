"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const testing_1 = require("@nestjs/testing");
const typeorm_1 = require("@nestjs/typeorm");
const jwt_1 = require("@nestjs/jwt");
const common_1 = require("@nestjs/common");
const argon2 = __importStar(require("argon2"));
const token_service_1 = require("./token.service");
const refresh_token_entity_1 = require("../entities/refresh-token.entity");
describe('TokenService', () => {
    let service;
    let jwtService;
    let refreshTokenRepo;
    beforeEach(async () => {
        const mockJwtService = {
            sign: jest.fn().mockReturnValue('mock-jwt-access-token'),
        };
        const mockRefreshTokenRepo = {
            find: jest.fn(),
            save: jest.fn(),
            update: jest.fn(),
        };
        const module = await testing_1.Test.createTestingModule({
            providers: [
                token_service_1.TokenService,
                { provide: jwt_1.JwtService, useValue: mockJwtService },
                { provide: (0, typeorm_1.getRepositoryToken)(refresh_token_entity_1.RefreshToken), useValue: mockRefreshTokenRepo },
            ],
        }).compile();
        service = module.get(token_service_1.TokenService);
        jwtService = module.get(jwt_1.JwtService);
        refreshTokenRepo = module.get((0, typeorm_1.getRepositoryToken)(refresh_token_entity_1.RefreshToken));
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
            expect(jwtService.sign).toHaveBeenCalledWith({ sub: 'user-123', publicKey: 'public-key-abc' }, { expiresIn: '15m' });
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
            expect(refreshTokenRepo.save).toHaveBeenCalledWith(expect.objectContaining({
                tokenHash: expect.stringMatching(/^\$argon2/),
            }));
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
            const expiresAt = saveCall.expiresAt;
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
                    tokenPrefix: refreshToken.substring(0, 16),
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
            await expect(service.rotateRefreshToken('invalid-token', 'user-123', 'public-key')).rejects.toThrow(common_1.UnauthorizedException);
            await expect(service.rotateRefreshToken('invalid-token', 'user-123', 'public-key')).rejects.toThrow('Invalid refresh token');
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
            await expect(service.rotateRefreshToken(refreshToken, 'user-123', 'public-key')).rejects.toThrow(common_1.UnauthorizedException);
            await expect(service.rotateRefreshToken(refreshToken, 'user-123', 'public-key')).rejects.toThrow('Refresh token expired');
            // Verify token was revoked
            expect(refreshTokenRepo.save).toHaveBeenCalledWith(expect.objectContaining({
                revokedAt: expect.any(Date),
            }));
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
            expect(refreshTokenRepo.save.mock.calls[0][0]).toEqual(expect.objectContaining({
                revokedAt: expect.any(Date),
            }));
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
            await expect(service.rotateRefreshToken('some-token', 'user-123', 'public-key')).rejects.toThrow(common_1.UnauthorizedException);
        });
        it('should continue checking tokens when argon2.verify returns false', async () => {
            const correctToken = 'correct-token';
            const correctTokenHash = await argon2.hash(correctToken);
            const wrongTokenHash = await argon2.hash('wrong-token');
            const tokens = [
                {
                    id: 'token-1',
                    userId: 'user-123',
                    tokenHash: wrongTokenHash, // This won't match
                    expiresAt: new Date(Date.now() + 86400000),
                    revokedAt: null,
                },
                {
                    id: 'token-2',
                    userId: 'user-123',
                    tokenHash: correctTokenHash, // This will match
                    expiresAt: new Date(Date.now() + 86400000),
                    revokedAt: null,
                },
            ];
            refreshTokenRepo.find.mockResolvedValue(tokens);
            refreshTokenRepo.save.mockResolvedValue({ ...tokens[1], revokedAt: new Date() });
            const result = await service.rotateRefreshToken(correctToken, 'user-123', 'public-key');
            // Should find the second token and rotate successfully
            expect(result.accessToken).toBeDefined();
            expect(result.refreshToken).toBeDefined();
        });
    });
    describe('revokeAllUserTokens', () => {
        it('should update all non-revoked tokens for user with revokedAt', async () => {
            refreshTokenRepo.update.mockResolvedValue({ affected: 3 });
            await service.revokeAllUserTokens('user-123');
            expect(refreshTokenRepo.update).toHaveBeenCalledWith({ userId: 'user-123', revokedAt: expect.anything() }, // IsNull()
            { revokedAt: expect.any(Date) });
        });
    });
    describe('revokeToken', () => {
        it('should update specific token with revokedAt', async () => {
            refreshTokenRepo.update.mockResolvedValue({ affected: 1 });
            await service.revokeToken('token-uuid');
            expect(refreshTokenRepo.update).toHaveBeenCalledWith({ id: 'token-uuid', revokedAt: expect.anything() }, // IsNull()
            { revokedAt: expect.any(Date) });
        });
    });
});
//# sourceMappingURL=token.service.spec.js.map