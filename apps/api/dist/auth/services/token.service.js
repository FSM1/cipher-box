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
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
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
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const argon2 = __importStar(require("argon2"));
const crypto_1 = require("crypto");
const refresh_token_entity_1 = require("../entities/refresh-token.entity");
let TokenService = class TokenService {
    jwtService;
    refreshTokenRepo;
    REFRESH_TOKEN_EXPIRY_DAYS = 7;
    constructor(jwtService, refreshTokenRepo) {
        this.jwtService = jwtService;
        this.refreshTokenRepo = refreshTokenRepo;
    }
    async createTokens(userId, publicKey) {
        // Generate access token
        const accessToken = this.jwtService.sign({ sub: userId, publicKey }, { expiresIn: '15m' });
        // Generate refresh token
        const refreshToken = (0, crypto_1.randomBytes)(32).toString('hex');
        const tokenHash = await argon2.hash(refreshToken);
        // Calculate expiry date
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_EXPIRY_DAYS);
        // Save to database with prefix for O(1) lookup
        const tokenPrefix = refreshToken.substring(0, 16);
        await this.refreshTokenRepo.save({
            userId,
            tokenHash,
            tokenPrefix,
            expiresAt,
        });
        return { accessToken, refreshToken };
    }
    async rotateRefreshToken(oldRefreshToken, userId, publicKey) {
        // Find candidate tokens by prefix for O(1) lookup instead of O(N) Argon2 scan
        const prefix = oldRefreshToken.substring(0, 16);
        const tokens = await this.refreshTokenRepo.find({
            where: {
                userId,
                tokenPrefix: prefix,
                revokedAt: (0, typeorm_2.IsNull)(),
            },
        });
        // Find matching token
        let validToken = null;
        for (const token of tokens) {
            try {
                if (await argon2.verify(token.tokenHash, oldRefreshToken)) {
                    validToken = token;
                    break;
                }
            }
            catch {
                // argon2.verify throws on invalid hash format, continue checking
                continue;
            }
        }
        if (!validToken) {
            throw new common_1.UnauthorizedException('Invalid refresh token');
        }
        if (validToken.expiresAt < new Date()) {
            // Revoke expired token
            validToken.revokedAt = new Date();
            await this.refreshTokenRepo.save(validToken);
            throw new common_1.UnauthorizedException('Refresh token expired');
        }
        // Revoke old token
        validToken.revokedAt = new Date();
        await this.refreshTokenRepo.save(validToken);
        // Create new tokens
        return this.createTokens(userId, publicKey);
    }
    async revokeAllUserTokens(userId) {
        await this.refreshTokenRepo.update({ userId, revokedAt: (0, typeorm_2.IsNull)() }, { revokedAt: new Date() });
    }
    async revokeToken(tokenId) {
        await this.refreshTokenRepo.update({ id: tokenId, revokedAt: (0, typeorm_2.IsNull)() }, { revokedAt: new Date() });
    }
};
exports.TokenService = TokenService;
exports.TokenService = TokenService = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, typeorm_1.InjectRepository)(refresh_token_entity_1.RefreshToken)),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        typeorm_2.Repository])
], TokenService);
//# sourceMappingURL=token.service.js.map