import { WorkerListener } from 'bullmq';
/**
 * @publicApi
 */
export interface OnWorkerEventMetadata {
    eventName: keyof WorkerListener;
}
/**
 * Registers a worker event listener.
 * Class that contains worker event listeners must be annotated
 * with the "Processor" decorator.
 *
 * @publicApi
 */
export declare const OnWorkerEvent: (eventName: keyof WorkerListener) => MethodDecorator;
//# sourceMappingURL=on-worker-event.decorator.d.ts.map