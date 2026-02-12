"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFlowProducerToken = getFlowProducerToken;
function getFlowProducerToken(name) {
    return name ? `BullFlowProducer_${name}` : 'BullFlowProducer_default';
}
