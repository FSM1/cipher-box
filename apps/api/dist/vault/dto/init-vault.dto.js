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
exports.VaultResponseDto = exports.InitVaultDto = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
const tee_keys_dto_1 = require("../../tee/dto/tee-keys.dto");
/**
 * Request DTO for vault initialization
 * All byte fields are hex-encoded strings
 */
class InitVaultDto {
    ownerPublicKey;
    encryptedRootFolderKey;
    encryptedRootIpnsPrivateKey;
    rootIpnsPublicKey;
    rootIpnsName;
}
exports.InitVaultDto = InitVaultDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User secp256k1 public key (uncompressed, 65 bytes, hex-encoded)',
        example: '04a1b2c3d4e5f6...(130 hex characters for 65 bytes with 0x04 prefix)',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]+$/, { message: 'ownerPublicKey must be hex-encoded' }),
    __metadata("design:type", String)
], InitVaultDto.prototype, "ownerPublicKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'ECIES-wrapped root folder AES-256 key (hex-encoded)',
        example: 'a1b2c3d4e5f6...',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]+$/, {
        message: 'encryptedRootFolderKey must be hex-encoded',
    }),
    __metadata("design:type", String)
], InitVaultDto.prototype, "encryptedRootFolderKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'ECIES-wrapped Ed25519 IPNS private key (hex-encoded)',
        example: 'a1b2c3d4e5f6...',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]+$/, {
        message: 'encryptedRootIpnsPrivateKey must be hex-encoded',
    }),
    __metadata("design:type", String)
], InitVaultDto.prototype, "encryptedRootIpnsPrivateKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Ed25519 IPNS public key (32 bytes, hex-encoded)',
        example: 'a1b2c3d4e5f6...(64 hex characters for 32 bytes)',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]+$/, {
        message: 'rootIpnsPublicKey must be hex-encoded',
    }),
    __metadata("design:type", String)
], InitVaultDto.prototype, "rootIpnsPublicKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IPNS name (libp2p-key multihash, base58btc or base36)',
        example: 'k51qzi5uqu5dg...',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], InitVaultDto.prototype, "rootIpnsName", void 0);
/**
 * Response DTO for vault data
 */
class VaultResponseDto {
    id;
    ownerPublicKey;
    encryptedRootFolderKey;
    encryptedRootIpnsPrivateKey;
    rootIpnsPublicKey;
    rootIpnsName;
    createdAt;
    initializedAt;
    teeKeys;
}
exports.VaultResponseDto = VaultResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Vault UUID',
        example: '550e8400-e29b-41d4-a716-446655440000',
    }),
    __metadata("design:type", String)
], VaultResponseDto.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User secp256k1 public key (uncompressed, 65 bytes, hex-encoded)',
        example: '04a1b2c3d4e5f6...(130 hex characters for 65 bytes with 0x04 prefix)',
    }),
    __metadata("design:type", String)
], VaultResponseDto.prototype, "ownerPublicKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'ECIES-wrapped root folder AES-256 key (hex-encoded)',
        example: 'a1b2c3d4e5f6...',
    }),
    __metadata("design:type", String)
], VaultResponseDto.prototype, "encryptedRootFolderKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'ECIES-wrapped Ed25519 IPNS private key (hex-encoded)',
        example: 'a1b2c3d4e5f6...',
    }),
    __metadata("design:type", String)
], VaultResponseDto.prototype, "encryptedRootIpnsPrivateKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Ed25519 IPNS public key (32 bytes, hex-encoded)',
        example: 'a1b2c3d4e5f6...(64 hex characters for 32 bytes)',
    }),
    __metadata("design:type", String)
], VaultResponseDto.prototype, "rootIpnsPublicKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IPNS name for root folder',
        example: 'k51qzi5uqu5dg...',
    }),
    __metadata("design:type", String)
], VaultResponseDto.prototype, "rootIpnsName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Vault creation timestamp',
        example: '2026-01-20T12:00:00.000Z',
    }),
    __metadata("design:type", Date)
], VaultResponseDto.prototype, "createdAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'When vault was first used (first file uploaded), null if unused',
        example: '2026-01-20T13:00:00.000Z',
        nullable: true,
    }),
    __metadata("design:type", Object)
], VaultResponseDto.prototype, "initializedAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'TEE public keys for IPNS key encryption (null if TEE not initialized)',
        required: false,
        nullable: true,
        type: () => tee_keys_dto_1.TeeKeysDto,
    }),
    __metadata("design:type", Object)
], VaultResponseDto.prototype, "teeKeys", void 0);
//# sourceMappingURL=init-vault.dto.js.map