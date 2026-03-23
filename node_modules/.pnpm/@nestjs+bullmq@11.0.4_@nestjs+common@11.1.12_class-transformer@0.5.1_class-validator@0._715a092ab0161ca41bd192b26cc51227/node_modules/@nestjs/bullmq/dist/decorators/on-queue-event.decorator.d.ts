import { QueueEventsListener } from 'bullmq';
/**
 * @publicApi
 */
export interface OnQueueEventMetadata {
    eventName: keyof QueueEventsListener;
}
/**
 * Registers a queue event listener.
 * Class that contains queue event listeners must be annotated
 * with the "QueueEventsListener" decorator.
 *
 * @publicApi
 */
export declare const OnQueueEvent: (eventName: keyof QueueEventsListener) => MethodDecorator;
//# sourceMappingURL=on-queue-event.decorator.d.ts.map