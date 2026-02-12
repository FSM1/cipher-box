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
exports.QuotaResponseDto = void 0;
const swagger_1 = require("@nestjs/swagger");
/**
 * Response DTO for storage quota information
 */
class QuotaResponseDto {
    usedBytes;
    limitBytes;
    remainingBytes;
}
exports.QuotaResponseDto = QuotaResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Current storage usage in bytes',
        example: 104857600,
    }),
    __metadata("design:type", Number)
], QuotaResponseDto.prototype, "usedBytes", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Maximum storage limit in bytes (500 MiB)',
        example: 524288000,
    }),
    __metadata("design:type", Number)
], QuotaResponseDto.prototype, "limitBytes", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Remaining storage in bytes',
        example: 419430400,
    }),
    __metadata("design:type", Number)
], QuotaResponseDto.prototype, "remainingBytes", void 0);
//# sourceMappingURL=quota.dto.js.map