"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OnWorkerEvent = void 0;
const common_1 = require("@nestjs/common");
const bull_constants_1 = require("../bull.constants");
/**
 * Registers a worker event listener.
 * Class that contains worker event listeners must be annotated
 * with the "Processor" decorator.
 *
 * @publicApi
 */
const OnWorkerEvent = (eventName) => (0, common_1.SetMetadata)(bull_constants_1.ON_WORKER_EVENT_METADATA, {
    eventName: eventName,
});
exports.OnWorkerEvent = OnWorkerEvent;
