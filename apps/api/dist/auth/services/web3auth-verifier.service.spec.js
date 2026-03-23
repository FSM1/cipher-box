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
const common_1 = require("@nestjs/common");
const jose = __importStar(require("jose"));
const web3auth_verifier_service_1 = require("./web3auth-verifier.service");
// The jose module is mocked via jest.config.js moduleNameMapper
const mockJwtVerify = jose.jwtVerify;
const mockCreateRemoteJWKSet = jose.createRemoteJWKSet;
describe('Web3AuthVerifierService', () => {
    let service;
    beforeEach(async () => {
        // Reset mocks
        mockJwtVerify.mockReset();
        mockCreateRemoteJWKSet.mockReset();
        mockCreateRemoteJWKSet.mockReturnValue(jest.fn());
        const module = await testing_1.Test.createTestingModule({
            providers: [web3auth_verifier_service_1.Web3AuthVerifierService],
        }).compile();
        service = module.get(web3auth_verifier_service_1.Web3AuthVerifierService);
    });
    afterEach(() => {
        jest.resetAllMocks();
    });
    describe('verifyIdToken', () => {
        it('should verify social login token against social JWKS endpoint', async () => {
            const mockPayload = {
                wallets: [{ type: 'web3auth_app_key', public_key: 'abc123', curve: 'secp256k1' }],
                verifier: 'google',
                email: 'test@example.com',
            };
            mockJwtVerify.mockResolvedValue({ payload: mockPayload });
            const result = await service.verifyIdToken('valid-token', 'abc123', 'social');
            expect(result).toEqual(mockPayload);
            expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(expect.objectContaining({
                href: 'https://api-auth.web3auth.io/jwks',
            }));
        });
        it('should verify external wallet token against external JWKS endpoint', async () => {
            const mockPayload = {
                wallets: [{ type: 'ethereum', address: '0x123abc' }],
            };
            mockJwtVerify.mockResolvedValue({ payload: mockPayload });
            const result = await service.verifyIdToken('valid-token', '0x123abc', 'external_wallet');
            expect(result).toEqual(mockPayload);
            expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(expect.objectContaining({
                href: 'https://authjs.web3auth.io/jwks',
            }));
        });
        it('should throw UnauthorizedException on invalid JWT', async () => {
            mockJwtVerify.mockRejectedValue(new Error('Invalid signature'));
            await expect(service.verifyIdToken('invalid-token', 'key', 'social')).rejects.toThrow(common_1.UnauthorizedException);
            await expect(service.verifyIdToken('invalid-token', 'key', 'social')).rejects.toThrow('Invalid Web3Auth token: Invalid signature');
        });
        it('should throw UnauthorizedException if no secp256k1 public key (social)', async () => {
            const mockPayload = {
                wallets: [{ type: 'ethereum', address: '0x123' }], // No secp256k1 key
                verifier: 'google',
            };
            mockJwtVerify.mockResolvedValue({ payload: mockPayload });
            await expect(service.verifyIdToken('token', 'expected-key', 'social')).rejects.toThrow(common_1.UnauthorizedException);
            await expect(service.verifyIdToken('token', 'expected-key', 'social')).rejects.toThrow('No secp256k1 public key found in token');
        });
        it('should throw UnauthorizedException if public key mismatch (social)', async () => {
            const mockPayload = {
                wallets: [{ type: 'web3auth_app_key', public_key: 'different-key', curve: 'secp256k1' }],
                verifier: 'google',
            };
            mockJwtVerify.mockResolvedValue({ payload: mockPayload });
            await expect(service.verifyIdToken('token', 'expected-key', 'social')).rejects.toThrow(common_1.UnauthorizedException);
            await expect(service.verifyIdToken('token', 'expected-key', 'social')).rejects.toThrow('Public key mismatch');
        });
        it('should throw UnauthorizedException if no ethereum address (external)', async () => {
            const mockPayload = {
                wallets: [{ type: 'web3auth_app_key', public_key: 'key123' }], // No ethereum wallet
            };
            mockJwtVerify.mockResolvedValue({ payload: mockPayload });
            await expect(service.verifyIdToken('token', '0xExpected', 'external_wallet')).rejects.toThrow(common_1.UnauthorizedException);
            await expect(service.verifyIdToken('token', '0xExpected', 'external_wallet')).rejects.toThrow('No ethereum address found in token');
        });
        it('should throw UnauthorizedException if address mismatch (external, case-insensitive)', async () => {
            const mockPayload = {
                wallets: [{ type: 'ethereum', address: '0xDifferentAddress' }],
            };
            mockJwtVerify.mockResolvedValue({ payload: mockPayload });
            await expect(service.verifyIdToken('token', '0xExpectedAddress', 'external_wallet')).rejects.toThrow(common_1.UnauthorizedException);
            await expect(service.verifyIdToken('token', '0xExpectedAddress', 'external_wallet')).rejects.toThrow('Wallet address mismatch');
        });
        it('should match addresses case-insensitively (external)', async () => {
            const mockPayload = {
                wallets: [{ type: 'ethereum', address: '0xABC123DEF' }],
            };
            mockJwtVerify.mockResolvedValue({ payload: mockPayload });
            // Same address, different case - should succeed
            const result = await service.verifyIdToken('token', '0xabc123def', 'external_wallet');
            expect(result).toEqual(mockPayload);
        });
    });
    describe('extractIdentifier', () => {
        it('should return email if present', () => {
            const payload = { email: 'test@example.com', verifierId: 'id123' };
            const result = service.extractIdentifier(payload);
            expect(result).toBe('test@example.com');
        });
        it('should return verifierId if no email', () => {
            const payload = { verifierId: 'github|12345' };
            const result = service.extractIdentifier(payload);
            expect(result).toBe('github|12345');
        });
        it('should return wallet address if no verifierId', () => {
            const payload = { wallets: [{ type: 'ethereum', address: '0x123abc' }] };
            const result = service.extractIdentifier(payload);
            expect(result).toBe('0x123abc');
        });
        it('should return public key as last resort', () => {
            const payload = { wallets: [{ type: 'ethereum', public_key: 'pubkey123' }] };
            const result = service.extractIdentifier(payload);
            expect(result).toBe('pubkey123');
        });
        it('should throw UnauthorizedException if no identifier', () => {
            const payload = { wallets: [] };
            expect(() => service.extractIdentifier(payload)).toThrow(common_1.UnauthorizedException);
            expect(() => service.extractIdentifier(payload)).toThrow('No identifier found in token');
        });
        it('should throw UnauthorizedException if empty payload', () => {
            const payload = {};
            expect(() => service.extractIdentifier(payload)).toThrow(common_1.UnauthorizedException);
        });
    });
    describe('extractAuthMethodType', () => {
        it("should return 'external_wallet' for external_wallet loginType", () => {
            const payload = { verifier: 'any' };
            const result = service.extractAuthMethodType(payload, 'external_wallet');
            expect(result).toBe('external_wallet');
        });
        it("should return 'google' if verifier contains 'google'", () => {
            const payload = { verifier: 'tkey-google' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('google');
        });
        it("should return 'apple' if verifier contains 'apple'", () => {
            const payload = { verifier: 'tkey-apple-prod' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('apple');
        });
        it("should return 'github' if verifier contains 'github'", () => {
            const payload = { verifier: 'tkey-github' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('github');
        });
        it("should return 'email_passwordless' if verifier contains 'email'", () => {
            const payload = { verifier: 'tkey-email-passwordless' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('email_passwordless');
        });
        it("should return 'email_passwordless' if verifier contains 'passwordless'", () => {
            const payload = { verifier: 'auth0-passwordless-prod' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('email_passwordless');
        });
        it("should return 'email_passwordless' as default if email present", () => {
            const payload = { verifier: 'unknown-provider', email: 'user@example.com' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('email_passwordless');
        });
        it("should return 'email_passwordless' as fallback for unknown verifier", () => {
            const payload = { verifier: 'unknown-provider' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('email_passwordless');
        });
        it("should detect 'google' from aggregateVerifier", () => {
            const payload = { verifier: 'some-verifier', aggregateVerifier: 'tkey-google-aggregate' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('google');
        });
        it("should detect 'apple' from aggregateVerifier", () => {
            const payload = { aggregateVerifier: 'tkey-apple-aggregate' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('apple');
        });
        it("should detect 'github' from aggregateVerifier", () => {
            const payload = { aggregateVerifier: 'tkey-github-aggregate' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('github');
        });
        it("should detect 'email_passwordless' from aggregateVerifier containing 'email'", () => {
            const payload = { aggregateVerifier: 'tkey-email-aggregate' };
            const result = service.extractAuthMethodType(payload, 'social');
            expect(result).toBe('email_passwordless');
        });
    });
});
//# sourceMappingURL=web3auth-verifier.service.spec.js.map