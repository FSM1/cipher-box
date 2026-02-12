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
exports.UploadResponseDto = void 0;
const swagger_1 = require("@nestjs/swagger");
class UploadResponseDto {
    cid;
    size;
    recorded;
}
exports.UploadResponseDto = UploadResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'The IPFS CID of the pinned file',
        example: 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
    }),
    __metadata("design:type", String)
], UploadResponseDto.prototype, "cid", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'The size of the pinned file in bytes',
        example: 1024,
    }),
    __metadata("design:type", Number)
], UploadResponseDto.prototype, "size", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the pin was recorded for quota tracking',
        example: true,
    }),
    __metadata("design:type", Boolean)
], UploadResponseDto.prototype, "recorded", void 0);
//# sourceMappingURL=upload.dto.js.map