"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OnQueueEvent = void 0;
const common_1 = require("@nestjs/common");
const bull_constants_1 = require("../bull.constants");
/**
 * Registers a queue event listener.
 * Class that contains queue event listeners must be annotated
 * with the "QueueEventsListener" decorator.
 *
 * @publicApi
 */
const OnQueueEvent = (eventName) => (0, common_1.SetMetadata)(bull_constants_1.ON_QUEUE_EVENT_METADATA, { eventName });
exports.OnQueueEvent = OnQueueEvent;
