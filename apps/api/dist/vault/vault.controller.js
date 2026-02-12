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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.VaultController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const vault_service_1 = require("./vault.service");
const init_vault_dto_1 = require("./dto/init-vault.dto");
const vault_export_dto_1 = require("./dto/vault-export.dto");
const quota_dto_1 = require("./dto/quota.dto");
let VaultController = class VaultController {
    vaultService;
    constructor(vaultService) {
        this.vaultService = vaultService;
    }
    async initializeVault(req, dto) {
        return this.vaultService.initializeVault(req.user.id, dto);
    }
    async exportVault(req) {
        return this.vaultService.getExportData(req.user.id);
    }
    async getVault(req) {
        const vault = await this.vaultService.findVault(req.user.id);
        if (!vault) {
            throw new common_1.NotFoundException('Vault not found');
        }
        return vault;
    }
    async getQuota(req) {
        return this.vaultService.getQuota(req.user.id);
    }
};
exports.VaultController = VaultController;
__decorate([
    (0, common_1.Post)('init'),
    (0, swagger_1.ApiOperation)({
        summary: 'Initialize user vault',
        description: 'Create a new vault with encrypted keys on first sign-in. Returns 409 Conflict if vault already exists.',
    }),
    (0, swagger_1.ApiResponse)({
        status: 201,
        description: 'Vault initialized successfully',
        type: init_vault_dto_1.VaultResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    (0, swagger_1.ApiResponse)({
        status: 409,
        description: 'Conflict - Vault already exists for this user',
    }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, init_vault_dto_1.InitVaultDto]),
    __metadata("design:returntype", Promise)
], VaultController.prototype, "initializeVault", null);
__decorate([
    (0, common_1.Get)('export'),
    (0, swagger_1.ApiOperation)({
        summary: 'Export vault for independent recovery',
        description: 'Returns the minimal vault data needed for independent recovery: root IPNS name, encrypted root keys, and derivation hints.',
    }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Vault export data',
        type: vault_export_dto_1.VaultExportDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    (0, swagger_1.ApiResponse)({
        status: 404,
        description: 'Not Found - Vault does not exist',
    }),
    __param(0, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], VaultController.prototype, "exportVault", null);
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiOperation)({
        summary: 'Get user vault',
        description: 'Retrieve the vault for the authenticated user.',
    }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Vault retrieved successfully',
        type: init_vault_dto_1.VaultResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    (0, swagger_1.ApiResponse)({
        status: 404,
        description: 'Not Found - Vault does not exist',
    }),
    __param(0, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], VaultController.prototype, "getVault", null);
__decorate([
    (0, common_1.Get)('quota'),
    (0, swagger_1.ApiOperation)({
        summary: 'Get storage quota',
        description: 'Get current storage usage and limits. Limit is 500 MiB (524,288,000 bytes).',
    }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Quota retrieved successfully',
        type: quota_dto_1.QuotaResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    __param(0, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], VaultController.prototype, "getQuota", null);
exports.VaultController = VaultController = __decorate([
    (0, swagger_1.ApiTags)('Vault'),
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Controller)('vault'),
    __metadata("design:paramtypes", [vault_service_1.VaultService])
], VaultController);
//# sourceMappingURL=vault.controller.js.map