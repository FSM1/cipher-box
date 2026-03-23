"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NO_FLOW_PRODUCER_FOUND = exports.NO_QUEUE_FOUND = void 0;
const NO_QUEUE_FOUND = (name) => name
    ? `No Queue was found with the given name (${name}). Check your configuration.`
    : 'No Queue was found. Check your configuration.';
exports.NO_QUEUE_FOUND = NO_QUEUE_FOUND;
const NO_FLOW_PRODUCER_FOUND = (name) => name
    ? `No Flow Producer was found with the given name (${name}). Check your configuration.`
    : 'No Flow Producer was found. Check your configuration.';
exports.NO_FLOW_PRODUCER_FOUND = NO_FLOW_PRODUCER_FOUND;
