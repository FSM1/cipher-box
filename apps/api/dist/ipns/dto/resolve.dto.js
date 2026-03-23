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
exports.ResolveIpnsResponseDto = exports.ResolveIpnsQueryDto = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
class ResolveIpnsQueryDto {
    ipnsName;
}
exports.ResolveIpnsQueryDto = ResolveIpnsQueryDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IPNS name to resolve. Supports CIDv1 IPNS names starting with "k51..." (PeerID-style) or "bafzaa..." (IPNS key CID).',
        example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)()
    // [SECURITY: MEDIUM-12] IPNS name validation - accept k51 (base36) or bafzaa (base32) CIDv1 libp2p-key
    // k51qzi5uqu5 (11 chars) + 40-60 = 51-71 chars; bafzaa (6 chars) + 50-70 = 56-76 chars
    ,
    (0, class_validator_1.Matches)(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
        message: 'ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
    }),
    (0, class_validator_1.MaxLength)(76),
    __metadata("design:type", String)
], ResolveIpnsQueryDto.prototype, "ipnsName", void 0);
class ResolveIpnsResponseDto {
    success;
    cid;
    sequenceNumber;
    signatureV2;
    data;
    pubKey;
}
exports.ResolveIpnsResponseDto = ResolveIpnsResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the resolution succeeded',
        example: true,
    }),
    __metadata("design:type", Boolean)
], ResolveIpnsResponseDto.prototype, "success", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'CID that the IPNS name currently points to',
        example: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
    }),
    __metadata("design:type", String)
], ResolveIpnsResponseDto.prototype, "cid", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Current sequence number of the IPNS record (bigint as string)',
        example: '1',
    }),
    __metadata("design:type", String)
], ResolveIpnsResponseDto.prototype, "sequenceNumber", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Base64-encoded Ed25519 signature (64 bytes) from the IPNS record. ' +
            'Only present when resolved from delegated routing (not DB cache).',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ResolveIpnsResponseDto.prototype, "signatureV2", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Base64-encoded CBOR data that was signed. ' +
            'Only present when resolved from delegated routing (not DB cache).',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ResolveIpnsResponseDto.prototype, "data", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Base64-encoded raw Ed25519 public key (32 bytes). ' +
            'Only present when resolved from delegated routing (not DB cache).',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ResolveIpnsResponseDto.prototype, "pubKey", void 0);
//# sourceMappingURL=resolve.dto.js.map