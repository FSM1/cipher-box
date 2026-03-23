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
exports.PublishIpnsResponseDto = exports.PublishIpnsDto = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
class PublishIpnsDto {
    ipnsName;
    record;
    metadataCid;
    encryptedIpnsPrivateKey;
    keyEpoch;
}
exports.PublishIpnsDto = PublishIpnsDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IPNS name (k51... CIDv1 format)',
        example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)()
    // [SECURITY: MEDIUM-12] IPNS name validation - accept k51 (base36) or bafzaa (base32) CIDv1 libp2p-key
    // Both formats are accepted for forward compatibility and external tool support.
    // Client code generates base36 (k51...) format, but we accept base32 (bafzaa...) for interoperability.
    ,
    (0, class_validator_1.Matches)(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
        message: 'ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
    }),
    (0, class_validator_1.MaxLength)(70),
    __metadata("design:type", String)
], PublishIpnsDto.prototype, "ipnsName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Base64-encoded marshaled IPNS record',
        example: 'CiQBqKAFp...',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsBase64)(),
    (0, class_validator_1.MaxLength)(10000) // IPNS records should be small
    ,
    __metadata("design:type", String)
], PublishIpnsDto.prototype, "record", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'CID of the encrypted metadata this record points to',
        example: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)()
    // [SECURITY: MEDIUM-10] Validate CID format - must start with bafy/bafk (CIDv1) or Qm (CIDv0)
    ,
    (0, class_validator_1.Matches)(/^(bafy|bafk|Qm)[a-zA-Z0-9]+$/, {
        message: 'metadataCid must be a valid CID (bafy..., bafk..., or Qm...)',
    }),
    (0, class_validator_1.MaxLength)(100),
    __metadata("design:type", String)
], PublishIpnsDto.prototype, "metadataCid", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Hex-encoded ECIES-wrapped Ed25519 private key for TEE republishing (required on first publish)',
        required: false,
        example: '04abcd1234...',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)()
    // [SECURITY: MEDIUM-09] Validate hex format and reasonable length for ECIES ciphertext
    ,
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]+$/, {
        message: 'encryptedIpnsPrivateKey must be hex-encoded',
    }),
    (0, class_validator_1.MinLength)(100, {
        message: 'encryptedIpnsPrivateKey too short for ECIES ciphertext',
    }),
    (0, class_validator_1.MaxLength)(1000, {
        message: 'encryptedIpnsPrivateKey too long',
    }),
    __metadata("design:type", String)
], PublishIpnsDto.prototype, "encryptedIpnsPrivateKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'TEE key epoch (required with encryptedIpnsPrivateKey)',
        required: false,
        example: 1,
    }),
    (0, class_validator_1.IsNumber)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Number)
], PublishIpnsDto.prototype, "keyEpoch", void 0);
class PublishIpnsResponseDto {
    success;
    ipnsName;
    sequenceNumber;
}
exports.PublishIpnsResponseDto = PublishIpnsResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the publish operation succeeded',
        example: true,
    }),
    __metadata("design:type", Boolean)
], PublishIpnsResponseDto.prototype, "success", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IPNS name that was published',
        example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
    }),
    __metadata("design:type", String)
], PublishIpnsResponseDto.prototype, "ipnsName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Current sequence number (bigint as string)',
        example: '1',
    }),
    __metadata("design:type", String)
], PublishIpnsResponseDto.prototype, "sequenceNumber", void 0);
//# sourceMappingURL=publish.dto.js.map