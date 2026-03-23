"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidProcessorClassError = void 0;
/**
 * @publicApi
 */
class InvalidProcessorClassError extends Error {
    constructor(className) {
        super(`Processor class ("${className}") should inherit from the abstract "WorkerHost" class.`);
    }
}
exports.InvalidProcessorClassError = InvalidProcessorClassError;
