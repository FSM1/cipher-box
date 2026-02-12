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
var RepublishProcessor_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.RepublishProcessor = void 0;
const bullmq_1 = require("@nestjs/bullmq");
const common_1 = require("@nestjs/common");
const republish_service_1 = require("./republish.service");
let RepublishProcessor = RepublishProcessor_1 = class RepublishProcessor extends bullmq_1.WorkerHost {
    republishService;
    logger = new common_1.Logger(RepublishProcessor_1.name);
    constructor(republishService) {
        super();
        this.republishService = republishService;
    }
    async process(job) {
        this.logger.log(`Republish job started: ${job.name} (id: ${job.id})`);
        try {
            const result = await this.republishService.processRepublishBatch();
            this.logger.log(`Republish job complete: processed=${result.processed}, succeeded=${result.succeeded}, failed=${result.failed}`);
            // If all entries failed and none succeeded, TEE might be down.
            // When TEE recovers, reactivate stale entries.
            if (result.processed > 0 && result.succeeded === 0 && result.failed === result.processed) {
                this.logger.warn('All republish entries failed. TEE worker may be unreachable.');
            }
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger.error(`Republish job failed: ${message}`);
            throw error; // Let BullMQ handle retry
        }
    }
};
exports.RepublishProcessor = RepublishProcessor;
exports.RepublishProcessor = RepublishProcessor = RepublishProcessor_1 = __decorate([
    (0, bullmq_1.Processor)('republish'),
    __metadata("design:paramtypes", [republish_service_1.RepublishService])
], RepublishProcessor);
//# sourceMappingURL=republish.processor.js.map