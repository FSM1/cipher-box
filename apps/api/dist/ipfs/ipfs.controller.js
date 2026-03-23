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
exports.IpfsController = void 0;
const common_1 = require("@nestjs/common");
const platform_express_1 = require("@nestjs/platform-express");
const swagger_1 = require("@nestjs/swagger");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const providers_1 = require("./providers");
const dto_1 = require("./dto");
const vault_service_1 = require("../vault/vault.service");
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
let IpfsController = class IpfsController {
    ipfsProvider;
    vaultService;
    constructor(ipfsProvider, vaultService) {
        this.ipfsProvider = ipfsProvider;
        this.vaultService = vaultService;
    }
    async upload(req, file) {
        const hasQuota = await this.vaultService.checkQuota(req.user.id, file.size);
        if (!hasQuota)
            throw new common_1.PayloadTooLargeException('Storage quota exceeded');
        const result = await this.ipfsProvider.pinFile(file.buffer);
        try {
            await this.vaultService.recordPin(req.user.id, result.cid, result.size);
        }
        catch (err) {
            await this.ipfsProvider.unpinFile(result.cid).catch(() => undefined);
            throw err;
        }
        return { cid: result.cid, size: result.size, recorded: true };
    }
    async unpin(dto) {
        await this.ipfsProvider.unpinFile(dto.cid);
        return { success: true };
    }
    async get(cid, res) {
        const buffer = await this.ipfsProvider.getFile(cid);
        res.set({
            'Content-Type': 'application/octet-stream',
            'Content-Length': buffer.length.toString(),
        });
        return new common_1.StreamableFile(buffer);
    }
};
exports.IpfsController = IpfsController;
__decorate([
    (0, common_1.Post)('upload'),
    (0, swagger_1.ApiOperation)({
        summary: 'Upload encrypted file to IPFS with quota tracking',
        description: 'Pins encrypted file to IPFS, checks storage quota, and records the pin for quota tracking. All in one atomic request.',
    }),
    (0, swagger_1.ApiConsumes)('multipart/form-data'),
    (0, swagger_1.ApiBody)({
        schema: {
            type: 'object',
            properties: {
                file: {
                    type: 'string',
                    format: 'binary',
                    description: 'Encrypted file blob (max 100MB)',
                },
            },
            required: ['file'],
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: 201,
        description: 'File uploaded, pinned, and recorded successfully',
        type: dto_1.UploadResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    (0, swagger_1.ApiResponse)({
        status: 413,
        description: 'Storage quota exceeded',
    }),
    (0, common_1.UseInterceptors)((0, platform_express_1.FileInterceptor)('file', {
        limits: { fileSize: MAX_FILE_SIZE },
    })),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.UploadedFile)(new common_1.ParseFilePipe({
        validators: [new common_1.MaxFileSizeValidator({ maxSize: MAX_FILE_SIZE })],
    }))),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], IpfsController.prototype, "upload", null);
__decorate([
    (0, common_1.Post)('unpin'),
    (0, swagger_1.ApiOperation)({
        summary: 'Unpin file from IPFS',
        description: 'Remove a pinned file from IPFS via Pinata using its CID.',
    }),
    (0, swagger_1.ApiResponse)({
        status: 201,
        description: 'File unpinned successfully',
        type: dto_1.UnpinResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [dto_1.UnpinDto]),
    __metadata("design:returntype", Promise)
], IpfsController.prototype, "unpin", null);
__decorate([
    (0, common_1.Get)(':cid'),
    (0, swagger_1.ApiOperation)({
        summary: 'Get file from IPFS',
        description: 'Download an encrypted file from IPFS via the configured gateway.',
    }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'File retrieved successfully',
        content: {
            'application/octet-stream': {
                schema: {
                    type: 'string',
                    format: 'binary',
                },
            },
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    (0, swagger_1.ApiResponse)({
        status: 404,
        description: 'File not found',
    }),
    __param(0, (0, common_1.Param)('cid')),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], IpfsController.prototype, "get", null);
exports.IpfsController = IpfsController = __decorate([
    (0, swagger_1.ApiTags)('IPFS'),
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Controller)('ipfs'),
    __param(0, (0, common_1.Inject)(providers_1.IPFS_PROVIDER)),
    __metadata("design:paramtypes", [Object, vault_service_1.VaultService])
], IpfsController);
//# sourceMappingURL=ipfs.controller.js.map