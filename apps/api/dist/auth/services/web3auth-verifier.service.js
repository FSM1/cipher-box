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
Object.defineProperty(exports, "__esModule", { value: true });
exports.Web3AuthVerifierService = void 0;
const common_1 = require("@nestjs/common");
const jose = __importStar(require("jose"));
const JWKS_ENDPOINTS = {
    social: 'https://api-auth.web3auth.io/jwks',
    external_wallet: 'https://authjs.web3auth.io/jwks',
};
let Web3AuthVerifierService = class Web3AuthVerifierService {
    jwksCache = new Map();
    getJwks(loginType) {
        const url = JWKS_ENDPOINTS[loginType];
        if (!this.jwksCache.has(url)) {
            this.jwksCache.set(url, jose.createRemoteJWKSet(new URL(url)));
        }
        return this.jwksCache.get(url);
    }
    async verifyIdToken(idToken, expectedPublicKeyOrAddress, loginType) {
        const jwks = this.getJwks(loginType);
        let payload;
        try {
            const result = await jose.jwtVerify(idToken, jwks, {
                algorithms: ['ES256'],
            });
            payload = result.payload;
        }
        catch (error) {
            throw new common_1.UnauthorizedException(`Invalid Web3Auth token: ${error instanceof Error ? error.message : 'verification failed'}`);
        }
        // Verify wallet/public key matches based on login type
        if (loginType === 'social') {
            const walletKey = payload.wallets?.find((w) => w.type === 'web3auth_app_key' && w.curve === 'secp256k1');
            if (!walletKey?.public_key) {
                throw new common_1.UnauthorizedException('No secp256k1 public key found in token');
            }
            if (walletKey.public_key !== expectedPublicKeyOrAddress) {
                throw new common_1.UnauthorizedException('Public key mismatch');
            }
        }
        else {
            const wallet = payload.wallets?.find((w) => w.type === 'ethereum');
            if (!wallet?.address) {
                throw new common_1.UnauthorizedException('No ethereum address found in token');
            }
            if (wallet.address.toLowerCase() !== expectedPublicKeyOrAddress.toLowerCase()) {
                throw new common_1.UnauthorizedException('Wallet address mismatch');
            }
        }
        return payload;
    }
    extractIdentifier(payload) {
        // Extract the most meaningful identifier from the payload
        if (payload.email) {
            return payload.email;
        }
        if (payload.verifierId) {
            return payload.verifierId;
        }
        // Fallback to wallet address or public key
        const wallet = payload.wallets?.[0];
        if (wallet?.address) {
            return wallet.address;
        }
        if (wallet?.public_key) {
            return wallet.public_key;
        }
        throw new common_1.UnauthorizedException('No identifier found in token');
    }
    extractAuthMethodType(payload, loginType) {
        if (loginType === 'external_wallet') {
            return 'external_wallet';
        }
        // Detect auth method from verifier
        const verifier = payload.verifier?.toLowerCase() || '';
        const aggregateVerifier = payload.aggregateVerifier?.toLowerCase() || '';
        if (verifier.includes('google') || aggregateVerifier.includes('google')) {
            return 'google';
        }
        if (verifier.includes('apple') || aggregateVerifier.includes('apple')) {
            return 'apple';
        }
        if (verifier.includes('github') || aggregateVerifier.includes('github')) {
            return 'github';
        }
        if (verifier.includes('email') ||
            verifier.includes('passwordless') ||
            aggregateVerifier.includes('email')) {
            return 'email_passwordless';
        }
        // Default to email_passwordless if email is present
        if (payload.email) {
            return 'email_passwordless';
        }
        // Fallback
        return 'email_passwordless';
    }
};
exports.Web3AuthVerifierService = Web3AuthVerifierService;
exports.Web3AuthVerifierService = Web3AuthVerifierService = __decorate([
    (0, common_1.Injectable)()
], Web3AuthVerifierService);
//# sourceMappingURL=web3auth-verifier.service.js.map