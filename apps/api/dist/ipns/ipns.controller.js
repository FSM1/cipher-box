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
exports.IpnsController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const throttler_1 = require("@nestjs/throttler");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const ipns_service_1 = require("./ipns.service");
const dto_1 = require("./dto");
let IpnsController = class IpnsController {
    ipnsService;
    constructor(ipnsService) {
        this.ipnsService = ipnsService;
    }
    // [SECURITY: HIGH-04] Rate limit IPNS publish to prevent abuse
    // Each publish makes external HTTP calls to delegated-ipfs.dev
    async publishRecord(req, dto) {
        return this.ipnsService.publishRecord(req.user.id, dto);
    }
    // [SECURITY: HIGH-04] Rate limit IPNS resolve - higher limit than publish since read-only
    async resolveRecord(query) {
        const result = await this.ipnsService.resolveRecord(query.ipnsName);
        if (!result) {
            throw new common_1.NotFoundException('IPNS name not found in routing network');
        }
        // Include signature fields as all-or-nothing bundle for client verification
        const hasSigData = result.signatureV2 && result.data && result.pubKey;
        return {
            success: true,
            cid: result.cid,
            sequenceNumber: result.sequenceNumber,
            ...(hasSigData && {
                signatureV2: result.signatureV2,
                data: result.data,
                pubKey: result.pubKey,
            }),
        };
    }
};
exports.IpnsController = IpnsController;
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 10, ttl: 60000 } }) // 10 publishes per minute per user
    ,
    (0, common_1.Post)('publish'),
    (0, swagger_1.ApiOperation)({
        summary: 'Publish IPNS record',
        description: 'Relay a pre-signed IPNS record to the IPFS network via delegated routing. ' +
            'The client signs the record locally; backend relays to delegated-ipfs.dev and tracks ' +
            'the folder for TEE republishing.',
    }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'IPNS record published successfully',
        type: dto_1.PublishIpnsResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 400,
        description: 'Bad Request - Invalid record format or missing required fields',
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    (0, swagger_1.ApiResponse)({
        status: 502,
        description: 'Bad Gateway - Failed to publish to delegated routing',
    }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, dto_1.PublishIpnsDto]),
    __metadata("design:returntype", Promise)
], IpnsController.prototype, "publishRecord", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 30, ttl: 60000 } }) // 30 resolves per minute per user
    ,
    (0, common_1.Get)('resolve'),
    (0, swagger_1.ApiOperation)({
        summary: 'Resolve IPNS name',
        description: 'Resolve an IPNS name to its current CID via delegated routing. ' +
            'Returns the CID and sequence number of the current IPNS record.',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'ipnsName',
        description: 'IPNS name to resolve. Supports CIDv1 IPNS names starting with "k51..." (PeerID-style) or "bafzaa..." (IPNS key CID).',
        example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
    }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'IPNS name resolved successfully',
        type: dto_1.ResolveIpnsResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 400,
        description: 'Bad Request - Invalid IPNS name format',
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized - JWT token required',
    }),
    (0, swagger_1.ApiResponse)({
        status: 404,
        description: 'Not Found - IPNS name not published or not found in routing network',
    }),
    (0, swagger_1.ApiResponse)({
        status: 502,
        description: 'Bad Gateway - Failed to resolve from delegated routing',
    }),
    __param(0, (0, common_1.Query)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [dto_1.ResolveIpnsQueryDto]),
    __metadata("design:returntype", Promise)
], IpnsController.prototype, "resolveRecord", null);
exports.IpnsController = IpnsController = __decorate([
    (0, swagger_1.ApiTags)('IPNS'),
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, throttler_1.ThrottlerGuard),
    (0, common_1.Controller)('ipns'),
    __metadata("design:paramtypes", [ipns_service_1.IpnsService])
], IpnsController);
//# sourceMappingURL=ipns.controller.js.map