import { Type } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { OnQueueEventMetadata, OnWorkerEventMetadata, ProcessorOptions, QueueEventsListenerOptions } from './decorators';
import { NestWorkerOptions } from './interfaces/worker-options.interface';
export declare class BullMetadataAccessor {
    private readonly reflector;
    constructor(reflector: Reflector);
    isProcessor(target: Type<any> | Function): boolean;
    isQueueEventsListener(target: Type<any> | Function): boolean;
    getProcessorMetadata(target: Type<any> | Function): ProcessorOptions | undefined;
    getWorkerOptionsMetadata(target: Type<any> | Function): NestWorkerOptions;
    getOnQueueEventMetadata(target: Type<any> | Function): OnQueueEventMetadata | undefined;
    getOnWorkerEventMetadata(target: Type<any> | Function): OnWorkerEventMetadata | undefined;
    getQueueEventsListenerMetadata(target: Type<any> | Function): QueueEventsListenerOptions | undefined;
}
//# sourceMappingURL=bull-metadata.accessor.d.ts.map