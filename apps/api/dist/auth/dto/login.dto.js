"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoginResponseDto = exports.LoginDto = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
class LoginDto {
    idToken;
    publicKey;
    loginType;
    walletAddress;
    derivationVersion;
}
exports.LoginDto = LoginDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT ID token from Web3Auth',
        example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginDto.prototype, "idToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'secp256k1 public key for social login, or signature-derived public key for external wallet (ADR-001)',
        example: '0x04...',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginDto.prototype, "publicKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Type of login used',
        enum: ['social', 'external_wallet'],
        example: 'social',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsIn)(['social', 'external_wallet']),
    __metadata("design:type", String)
], LoginDto.prototype, "loginType", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Wallet address for external wallet users. Used for JWT verification. The publicKey field contains the derived key.',
        example: '0x742d35Cc6634C0532925a3b844Bc9e7595f...',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginDto.prototype, "walletAddress", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Key derivation version for external wallet users (ADR-001). Required for external_wallet loginType.',
        example: 1,
        minimum: 1,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsInt)(),
    (0, class_validator_1.Min)(1),
    __metadata("design:type", Number)
], LoginDto.prototype, "derivationVersion", void 0);
class LoginResponseDto {
    accessToken;
    isNewUser;
    refreshToken;
}
exports.LoginResponseDto = LoginResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT access token for API requests',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    __metadata("design:type", String)
], LoginResponseDto.prototype, "accessToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether this is a new user registration',
        example: false,
    }),
    __metadata("design:type", Boolean)
], LoginResponseDto.prototype, "isNewUser", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Refresh token (only present for desktop clients using X-Client-Type: desktop header)',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    __metadata("design:type", String)
], LoginResponseDto.prototype, "refreshToken", void 0);
//# sourceMappingURL=login.dto.js.map