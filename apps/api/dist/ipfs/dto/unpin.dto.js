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
exports.UnpinResponseDto = exports.UnpinDto = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
class UnpinDto {
    cid;
}
exports.UnpinDto = UnpinDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'The IPFS CID of the file to unpin',
        example: 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], UnpinDto.prototype, "cid", void 0);
class UnpinResponseDto {
    success;
}
exports.UnpinResponseDto = UnpinResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the unpin operation was successful',
        example: true,
    }),
    __metadata("design:type", Boolean)
], UnpinResponseDto.prototype, "success", void 0);
//# sourceMappingURL=unpin.dto.js.map