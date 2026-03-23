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
exports.TeeKeysDto = void 0;
const swagger_1 = require("@nestjs/swagger");
/**
 * Response DTO for TEE public keys sent to clients.
 * Clients use the current TEE public key to encrypt IPNS private keys
 * before sending them to the backend for TEE republishing.
 */
class TeeKeysDto {
    currentEpoch;
    currentPublicKey;
    previousEpoch;
    previousPublicKey;
}
exports.TeeKeysDto = TeeKeysDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Current TEE key epoch number',
        example: 1,
    }),
    __metadata("design:type", Number)
], TeeKeysDto.prototype, "currentEpoch", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Current epoch TEE secp256k1 public key (uncompressed, 65 bytes, hex-encoded)',
        example: '04a1b2c3d4e5f6...(130 hex characters)',
    }),
    __metadata("design:type", String)
], TeeKeysDto.prototype, "currentPublicKey", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Previous TEE key epoch number (null if no rotation has occurred)',
        example: 0,
        nullable: true,
    }),
    __metadata("design:type", Object)
], TeeKeysDto.prototype, "previousEpoch", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Previous epoch TEE secp256k1 public key (hex-encoded, null if no rotation has occurred)',
        example: null,
        nullable: true,
    }),
    __metadata("design:type", Object)
], TeeKeysDto.prototype, "previousPublicKey", void 0);
//# sourceMappingURL=tee-keys.dto.js.map