"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFlowProducerOptionsToken = getFlowProducerOptionsToken;
function getFlowProducerOptionsToken(name) {
    return name
        ? `BullMQFlowProducerOptions_${name}`
        : 'BullMQFlowProducerOptions_default';
}
