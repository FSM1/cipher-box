"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QueueEventsListener = QueueEventsListener;
const common_1 = require("@nestjs/common");
const bull_constants_1 = require("../bull.constants");
/**
 * Represents a "QueueEvents" component (class that reacts to queue events).
 *
 * @publicApi
 */
function QueueEventsListener(queueName, queueEventsOptions) {
    return (target) => {
        (0, common_1.SetMetadata)(bull_constants_1.QUEUE_EVENTS_LISTENER_METADATA, {
            queueName,
            queueEventsOptions,
        })(target);
    };
}
