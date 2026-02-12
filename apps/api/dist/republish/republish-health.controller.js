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
exports.RepublishHealthController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const republish_service_1 = require("./republish.service");
let RepublishHealthController = class RepublishHealthController {
    republishService;
    constructor(republishService) {
        this.republishService = republishService;
    }
    async getHealth() {
        const stats = await this.republishService.getHealthStats();
        return {
            pending: stats.pending,
            failed: stats.failed,
            stale: stats.stale,
            lastRunAt: stats.lastRunAt,
            currentEpoch: stats.currentEpoch,
            teeHealthy: stats.teeHealthy,
        };
    }
};
exports.RepublishHealthController = RepublishHealthController;
__decorate([
    (0, common_1.Get)('republish-health'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, swagger_1.ApiOperation)({
        summary: 'Get IPNS republish health stats',
        description: 'Returns aggregate counts of pending, failed, and stale republish jobs, plus TEE connectivity status. Requires JWT authentication.',
    }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Republish health statistics',
        schema: {
            type: 'object',
            properties: {
                pending: {
                    type: 'number',
                    description: 'Active entries awaiting next republish cycle',
                },
                failed: {
                    type: 'number',
                    description: 'Entries currently in retry with exponential backoff',
                },
                stale: {
                    type: 'number',
                    description: 'Entries that exceeded max retries and need TEE recovery',
                },
                lastRunAt: {
                    type: 'string',
                    format: 'date-time',
                    nullable: true,
                    description: 'Timestamp of most recent successful republish',
                },
                currentEpoch: {
                    type: 'number',
                    nullable: true,
                    description: 'Current TEE key epoch number',
                },
                teeHealthy: {
                    type: 'boolean',
                    description: 'Whether the TEE worker is reachable and healthy',
                },
            },
        },
    }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Not authenticated' }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], RepublishHealthController.prototype, "getHealth", null);
exports.RepublishHealthController = RepublishHealthController = __decorate([
    (0, swagger_1.ApiTags)('Admin'),
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.Controller)('admin'),
    __metadata("design:paramtypes", [republish_service_1.RepublishService])
], RepublishHealthController);
//# sourceMappingURL=republish-health.controller.js.map