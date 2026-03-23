import { Scope } from '@nestjs/common';
import { NestWorkerOptions } from '../interfaces/worker-options.interface';
/**
 * @publicApi
 */
export interface ProcessorOptions {
    /**
     * Specifies the name of the queue to subscribe to.
     */
    name?: string;
    /**
     * Specifies the lifetime of an injected Processor.
     */
    scope?: Scope;
    /**
     * A key (configuration key) under which the queue/connection configuration should be available.
     */
    configKey?: string;
}
/**
 * Represents a worker that is able to process jobs from the queue.
 * @param queueName name of the queue to process
 *
 * @publicApi
 */
export declare function Processor(queueName: string): ClassDecorator;
/**
 * Represents a worker that is able to process jobs from the queue.
 * @param queueName name of the queue to process
 * @param workerOptions additional worker options
 *
 * @publicApi
 */
export declare function Processor(queueName: string, workerOptions: NestWorkerOptions): ClassDecorator;
/**
 * Represents a worker that is able to process jobs from the queue.
 * @param processorOptions processor options
 *
 * @publicApi
 */
export declare function Processor(processorOptions: ProcessorOptions): ClassDecorator;
/**
 * Represents a worker that is able to process jobs from the queue.
 * @param processorOptions processor options (Nest-specific)
 * @param workerOptions additional Bull worker options
 *
 * @publicApi
 */
export declare function Processor(processorOptions: ProcessorOptions, workerOptions: NestWorkerOptions): ClassDecorator;
//# sourceMappingURL=processor.decorator.d.ts.map