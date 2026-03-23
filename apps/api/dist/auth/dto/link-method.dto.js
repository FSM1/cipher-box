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
exports.UnlinkMethodResponseDto = exports.UnlinkMethodDto = exports.AuthMethodResponseDto = exports.LinkMethodDto = void 0;
const swagger_1 = require("@nestjs/swagger");
const class_validator_1 = require("class-validator");
class LinkMethodDto {
    idToken;
    loginType;
}
exports.LinkMethodDto = LinkMethodDto;
__decorate([
    (0, swagger_1.ApiProperty)({ description: 'Web3Auth ID token from the new auth method' }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LinkMethodDto.prototype, "idToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ description: 'Login type', enum: ['social', 'external_wallet'] }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsIn)(['social', 'external_wallet']),
    __metadata("design:type", String)
], LinkMethodDto.prototype, "loginType", void 0);
class AuthMethodResponseDto {
    id;
    type;
    identifier;
    lastUsedAt;
    createdAt;
}
exports.AuthMethodResponseDto = AuthMethodResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], AuthMethodResponseDto.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ enum: ['google', 'apple', 'github', 'email_passwordless', 'external_wallet'] }),
    __metadata("design:type", String)
], AuthMethodResponseDto.prototype, "type", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ description: 'Email or wallet address' }),
    __metadata("design:type", String)
], AuthMethodResponseDto.prototype, "identifier", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ nullable: true, type: Date }),
    __metadata("design:type", Object)
], AuthMethodResponseDto.prototype, "lastUsedAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", Date)
], AuthMethodResponseDto.prototype, "createdAt", void 0);
class UnlinkMethodDto {
    methodId;
}
exports.UnlinkMethodDto = UnlinkMethodDto;
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], UnlinkMethodDto.prototype, "methodId", void 0);
class UnlinkMethodResponseDto {
    success;
}
exports.UnlinkMethodResponseDto = UnlinkMethodResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", Boolean)
], UnlinkMethodResponseDto.prototype, "success", void 0);
//# sourceMappingURL=link-method.dto.js.map