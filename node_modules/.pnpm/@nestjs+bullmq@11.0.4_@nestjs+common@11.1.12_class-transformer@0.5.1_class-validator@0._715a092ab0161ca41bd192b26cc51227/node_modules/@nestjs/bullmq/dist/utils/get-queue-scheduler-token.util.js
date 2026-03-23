"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getQueueSchedulerToken = void 0;
function getQueueSchedulerToken(name) {
    return name ? `BullQueueScheduler_${name}` : 'BullQueueScheduler_default';
}
exports.getQueueSchedulerToken = getQueueSchedulerToken;
