"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidQueueEventsListenerClassError = void 0;
/**
 * @publicApi
 */
class InvalidQueueEventsListenerClassError extends Error {
    constructor(className) {
        super(`Queue events listener class ("${className}") should inherit from the abstract "QueueEventsHost" class.`);
    }
}
exports.InvalidQueueEventsListenerClassError = InvalidQueueEventsListenerClassError;
