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
var RepublishModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.RepublishModule = void 0;
const common_1 = require("@nestjs/common");
const bullmq_1 = require("@nestjs/bullmq");
const typeorm_1 = require("@nestjs/typeorm");
const config_1 = require("@nestjs/config");
const bullmq_2 = require("bullmq");
const republish_schedule_entity_1 = require("./republish-schedule.entity");
const folder_ipns_entity_1 = require("../ipns/entities/folder-ipns.entity");
const tee_module_1 = require("../tee/tee.module");
const republish_service_1 = require("./republish.service");
const republish_processor_1 = require("./republish.processor");
const republish_health_controller_1 = require("./republish-health.controller");
let RepublishModule = RepublishModule_1 = class RepublishModule {
    queue;
    logger = new common_1.Logger(RepublishModule_1.name);
    constructor(queue) {
        this.queue = queue;
    }
    async onModuleInit() {
        try {
            // Create repeating job scheduler: every 6 hours
            await this.queue.upsertJobScheduler('republish-cron', {
                pattern: '0 */6 * * *', // Every 6 hours: 00:00, 06:00, 12:00, 18:00
            }, {
                name: 'republish-batch',
            });
            this.logger.log('Republish cron scheduler registered: every 6 hours (0 */6 * * *)');
        }
        catch (error) {
            // Redis may be unavailable during development
            const message = error instanceof Error ? error.message : String(error);
            this.logger.warn(`Failed to register republish cron scheduler (non-fatal): ${message}`);
        }
    }
};
exports.RepublishModule = RepublishModule;
exports.RepublishModule = RepublishModule = RepublishModule_1 = __decorate([
    (0, common_1.Module)({
        imports: [
            bullmq_1.BullModule.registerQueue({ name: 'republish' }),
            typeorm_1.TypeOrmModule.forFeature([republish_schedule_entity_1.IpnsRepublishSchedule, folder_ipns_entity_1.FolderIpns]),
            tee_module_1.TeeModule,
            config_1.ConfigModule,
        ],
        providers: [republish_service_1.RepublishService, republish_processor_1.RepublishProcessor],
        controllers: [republish_health_controller_1.RepublishHealthController],
        exports: [republish_service_1.RepublishService],
    }),
    __param(0, (0, bullmq_1.InjectQueue)('republish')),
    __metadata("design:paramtypes", [bullmq_2.Queue])
], RepublishModule);
//# sourceMappingURL=republish.module.js.map