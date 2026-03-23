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
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const argon2 = __importStar(require("argon2"));
const user_entity_1 = require("./entities/user.entity");
const auth_method_entity_1 = require("./entities/auth-method.entity");
const refresh_token_entity_1 = require("./entities/refresh-token.entity");
const web3auth_verifier_service_1 = require("./services/web3auth-verifier.service");
const token_service_1 = require("./services/token.service");
let AuthService = class AuthService {
    web3AuthVerifier;
    tokenService;
    userRepository;
    authMethodRepository;
    refreshTokenRepository;
    constructor(web3AuthVerifier, tokenService, userRepository, authMethodRepository, refreshTokenRepository) {
        this.web3AuthVerifier = web3AuthVerifier;
        this.tokenService = tokenService;
        this.userRepository = userRepository;
        this.authMethodRepository = authMethodRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }
    async login(loginDto) {
        // 1. Verify Web3Auth token
        // For external wallets, verify against wallet address (from JWT), not derived public key
        const verificationKey = loginDto.loginType === 'external_wallet' && loginDto.walletAddress
            ? loginDto.walletAddress
            : loginDto.publicKey;
        const payload = await this.web3AuthVerifier.verifyIdToken(loginDto.idToken, verificationKey, loginDto.loginType);
        // 2. Find or create user
        let user = await this.userRepository.findOne({
            where: { publicKey: loginDto.publicKey },
        });
        // Determine derivation version for external wallets (ADR-001)
        const derivationVersion = loginDto.loginType === 'external_wallet' ? (loginDto.derivationVersion ?? 1) : null;
        const isNewUser = !user;
        if (!user) {
            user = await this.userRepository.save({
                publicKey: loginDto.publicKey,
                derivationVersion,
            });
        }
        else if (user.derivationVersion !== derivationVersion) {
            // Update derivation version if changed (e.g., migration to v2)
            user.derivationVersion = derivationVersion;
            await this.userRepository.save(user);
        }
        // 3. Find or create auth method
        const authMethodType = this.web3AuthVerifier.extractAuthMethodType(payload, loginDto.loginType);
        const identifier = this.web3AuthVerifier.extractIdentifier(payload);
        let authMethod = await this.authMethodRepository.findOne({
            where: {
                userId: user.id,
                type: authMethodType,
            },
        });
        if (!authMethod) {
            authMethod = await this.authMethodRepository.save({
                userId: user.id,
                type: authMethodType,
                identifier,
            });
        }
        // 4. Update last used timestamp
        authMethod.lastUsedAt = new Date();
        await this.authMethodRepository.save(authMethod);
        // 5. Create tokens
        const tokens = await this.tokenService.createTokens(user.id, user.publicKey);
        return {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            isNewUser,
        };
    }
    async refresh(refreshToken, userId, publicKey) {
        const tokens = await this.tokenService.rotateRefreshToken(refreshToken, userId, publicKey);
        return {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
        };
    }
    async logout(userId) {
        await this.tokenService.revokeAllUserTokens(userId);
        return { success: true };
    }
    /**
     * Refresh tokens by searching for the matching refresh token across all users.
     * This allows refresh without requiring the (possibly expired) access token.
     */
    async refreshByToken(refreshToken) {
        // Find candidate tokens by prefix for O(1) lookup instead of O(N) Argon2 scan
        const prefix = refreshToken.substring(0, 16);
        const tokens = await this.refreshTokenRepository.find({
            where: {
                tokenPrefix: prefix,
                revokedAt: (0, typeorm_2.IsNull)(),
            },
            relations: ['user'],
        });
        // Find matching token by verifying against hashes
        let validToken = null;
        for (const token of tokens) {
            // Skip expired tokens
            if (token.expiresAt < new Date()) {
                continue;
            }
            try {
                if (await argon2.verify(token.tokenHash, refreshToken)) {
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
            throw new common_1.UnauthorizedException('Invalid or expired refresh token');
        }
        // Revoke old token
        validToken.revokedAt = new Date();
        await this.refreshTokenRepository.save(validToken);
        // Create new tokens
        const newTokens = await this.tokenService.createTokens(validToken.userId, validToken.user.publicKey);
        return {
            accessToken: newTokens.accessToken,
            refreshToken: newTokens.refreshToken,
        };
    }
    /**
     * Get all linked auth methods for a user.
     */
    async getLinkedMethods(userId) {
        const methods = await this.authMethodRepository.find({
            where: { userId },
            order: { createdAt: 'ASC' },
        });
        return methods.map((method) => ({
            id: method.id,
            type: method.type,
            identifier: method.identifier,
            lastUsedAt: method.lastUsedAt,
            createdAt: method.createdAt,
        }));
    }
    /**
     * Link a new auth method to an existing user account.
     * CRITICAL: The new auth method's publicKey must match the user's publicKey
     * (ensuring both auth methods derive the same keypair via Web3Auth group connections)
     */
    async linkMethod(userId, linkDto) {
        // 1. Get the user to find their publicKey
        const user = await this.userRepository.findOne({ where: { id: userId } });
        if (!user) {
            throw new common_1.UnauthorizedException('User not found');
        }
        // 2. Verify the new idToken with Web3AuthVerifierService
        // This also validates that the new token's publicKey matches the user's publicKey
        const payload = await this.web3AuthVerifier.verifyIdToken(linkDto.idToken, user.publicKey, linkDto.loginType);
        // 3. Extract type and identifier from token payload
        const authMethodType = this.web3AuthVerifier.extractAuthMethodType(payload, linkDto.loginType);
        const identifier = this.web3AuthVerifier.extractIdentifier(payload);
        // 4. Check if this exact method (type + identifier) is already linked
        const existingMethod = await this.authMethodRepository.findOne({
            where: {
                userId,
                type: authMethodType,
                identifier,
            },
        });
        if (existingMethod) {
            throw new common_1.BadRequestException('This auth method is already linked to your account');
        }
        // 5. Create new AuthMethod entity
        await this.authMethodRepository.save({
            userId,
            type: authMethodType,
            identifier,
            lastUsedAt: new Date(),
        });
        // 6. Return updated list of methods
        return this.getLinkedMethods(userId);
    }
    /**
     * Unlink an auth method from a user account.
     * Cannot unlink the last remaining auth method.
     */
    async unlinkMethod(userId, methodId) {
        // 1. Find the method by id and userId
        const method = await this.authMethodRepository.findOne({
            where: { id: methodId, userId },
        });
        if (!method) {
            throw new common_1.BadRequestException('Auth method not found');
        }
        // 2. Count remaining methods for user
        const methodCount = await this.authMethodRepository.count({
            where: { userId },
        });
        // 3. Cannot unlink if only 1 method remains
        if (methodCount <= 1) {
            throw new common_1.BadRequestException('Cannot unlink your last auth method');
        }
        // 4. Delete the method
        await this.authMethodRepository.remove(method);
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __param(2, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __param(3, (0, typeorm_1.InjectRepository)(auth_method_entity_1.AuthMethod)),
    __param(4, (0, typeorm_1.InjectRepository)(refresh_token_entity_1.RefreshToken)),
    __metadata("design:paramtypes", [web3auth_verifier_service_1.Web3AuthVerifierService,
        token_service_1.TokenService,
        typeorm_2.Repository,
        typeorm_2.Repository,
        typeorm_2.Repository])
], AuthService);
//# sourceMappingURL=auth.service.js.map