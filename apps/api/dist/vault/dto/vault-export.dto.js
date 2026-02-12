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
exports.VaultExportDto = exports.DerivationInfoDto = void 0;
const swagger_1 = require("@nestjs/swagger");
/**
 * Derivation info hints how the user's private key was derived.
 * Helps recovery tools determine how to prompt for key input.
 */
class DerivationInfoDto {
    method;
    derivationVersion;
}
exports.DerivationInfoDto = DerivationInfoDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Authentication method used to derive the private key. "web3auth" = social login (key managed by Web3Auth MPC), "external-wallet" = EIP-712 signature-derived key.',
        example: 'web3auth',
        enum: ['web3auth', 'external-wallet'],
    }),
    __metadata("design:type", String)
], DerivationInfoDto.prototype, "method", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Key derivation version for external wallet users. null for social logins, 1+ for external wallet derivation versions.',
        example: 1,
        nullable: true,
    }),
    __metadata("design:type", Object)
], DerivationInfoDto.prototype, "derivationVersion", void 0);
/**
 * Response DTO for vault export.
 * Contains the minimal data needed for independent recovery:
 * root IPNS name + encrypted root keys.
 */
class VaultExportDto {
    format;
    version;
    exportedAt;
    rootIpnsName;
    encryptedRootFolderKey;
    encryptedRootIpnsPrivateKey;
    derivationInfo;
}
exports.VaultExportDto = VaultExportDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Export format identifier',
        example: 'cipherbox-vault-export',
    }),
    __metadata("design:type", String)
], VaultExportDto.prototype, "format", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Export format version',
        example: '1.0',
    }),
    __metadata("design:type", String)
], VaultExportDto.prototype, "version", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'ISO 8601 timestamp of when the export was created',
        example: '2026-02-11T12:00:00.000Z',
    }),
    __metadata("design:type", String)
], VaultExportDto.prototype, "exportedAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IPNS name for the root folder (libp2p-key multihash)',
        example: 'k51qzi5uqu5dg...',
    }),
    __metadata("design:type", String)
], VaultExportDto.prototype, "rootIpnsName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'ECIES-wrapped root folder AES-256 key (hex-encoded)',
        example: 'a1b2c3d4e5f6...',
    }),
    __metadata("design:type", String)
], VaultExportDto.prototype, "encryptedRootFolderKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'ECIES-wrapped Ed25519 IPNS private key (hex-encoded)',
        example: 'a1b2c3d4e5f6...',
    }),
    __metadata("design:type", String)
], VaultExportDto.prototype, "encryptedRootIpnsPrivateKey", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Hints about how the private key was derived, to assist recovery tools',
        type: DerivationInfoDto,
        nullable: true,
    }),
    __metadata("design:type", Object)
], VaultExportDto.prototype, "derivationInfo", void 0);
//# sourceMappingURL=vault-export.dto.js.map