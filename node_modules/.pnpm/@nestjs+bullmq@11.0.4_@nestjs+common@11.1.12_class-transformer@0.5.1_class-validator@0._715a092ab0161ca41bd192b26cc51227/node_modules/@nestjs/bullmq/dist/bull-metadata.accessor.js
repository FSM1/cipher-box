"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BullMetadataAccessor = void 0;
const tslib_1 = require("tslib");
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const bull_constants_1 = require("./bull.constants");
let BullMetadataAccessor = class BullMetadataAccessor {
    constructor(reflector) {
        this.reflector = reflector;
    }
    isProcessor(target) {
        if (!target) {
            return false;
        }
        return !!this.reflector.get(bull_constants_1.PROCESSOR_METADATA, target);
    }
    isQueueEventsListener(target) {
        if (!target) {
            return false;
        }
        return !!this.reflector.get(bull_constants_1.QUEUE_EVENTS_LISTENER_METADATA, target);
    }
    getProcessorMetadata(target) {
        return this.reflector.get(bull_constants_1.PROCESSOR_METADATA, target);
    }
    getWorkerOptionsMetadata(target) {
        return this.reflector.get(bull_constants_1.WORKER_METADATA, target) ?? {};
    }
    getOnQueueEventMetadata(target) {
        return this.reflector.get(bull_constants_1.ON_QUEUE_EVENT_METADATA, target);
    }
    getOnWorkerEventMetadata(target) {
        return this.reflector.get(bull_constants_1.ON_WORKER_EVENT_METADATA, target);
    }
    getQueueEventsListenerMetadata(target) {
        return this.reflector.get(bull_constants_1.QUEUE_EVENTS_LISTENER_METADATA, target);
    }
};
exports.BullMetadataAccessor = BullMetadataAccessor;
exports.BullMetadataAccessor = BullMetadataAccessor = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [core_1.Reflector])
], BullMetadataAccessor);
