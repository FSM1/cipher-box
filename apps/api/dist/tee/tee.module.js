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
var TeeModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.TeeModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const config_1 = require("@nestjs/config");
const tee_key_state_entity_1 = require("./tee-key-state.entity");
const tee_key_rotation_log_entity_1 = require("./tee-key-rotation-log.entity");
const tee_key_state_service_1 = require("./tee-key-state.service");
const tee_service_1 = require("./tee.service");
let TeeModule = TeeModule_1 = class TeeModule {
    teeService;
    logger = new common_1.Logger(TeeModule_1.name);
    constructor(teeService) {
        this.teeService = teeService;
    }
    async onModuleInit() {
        try {
            await this.teeService.initializeFromTee();
        }
        catch (error) {
            // Never crash the application if TEE is unavailable
            const message = error instanceof Error ? error.message : String(error);
            this.logger.warn(`TEE initialization failed (non-fatal): ${message}`);
        }
    }
};
exports.TeeModule = TeeModule;
exports.TeeModule = TeeModule = TeeModule_1 = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([tee_key_state_entity_1.TeeKeyState, tee_key_rotation_log_entity_1.TeeKeyRotationLog]), config_1.ConfigModule],
        providers: [tee_service_1.TeeService, tee_key_state_service_1.TeeKeyStateService],
        exports: [tee_service_1.TeeService, tee_key_state_service_1.TeeKeyStateService],
    }),
    __metadata("design:paramtypes", [tee_service_1.TeeService])
], TeeModule);
//# sourceMappingURL=tee.module.js.map