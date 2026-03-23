import { NestQueueEventOptions } from '../interfaces/queue-event-options.interface';
export type QueueEventsListenerOptions = {
    queueName: string;
    queueEventsOptions?: NestQueueEventOptions;
};
/**
 * Represents a "QueueEvents" component (class that reacts to queue events).
 *
 * @publicApi
 */
export declare function QueueEventsListener(queueName: string, queueEventsOptions?: NestQueueEventOptions): ClassDecorator;
//# sourceMappingURL=queue-events-listener.decorator.d.ts.map