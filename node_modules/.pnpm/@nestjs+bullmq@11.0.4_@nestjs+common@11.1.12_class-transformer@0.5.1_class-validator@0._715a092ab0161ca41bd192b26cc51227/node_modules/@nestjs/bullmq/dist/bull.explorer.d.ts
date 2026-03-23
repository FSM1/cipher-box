import { OnApplicationShutdown, Type } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, ModuleRef } from '@nestjs/core';
import { InstanceWrapper } from '@nestjs/core/injector/instance-wrapper';
import { Module } from '@nestjs/core/injector/module';
import { QueueEvents } from 'bullmq';
import { BullMetadataAccessor } from './bull-metadata.accessor';
import { OnQueueEventMetadata, OnWorkerEventMetadata } from './decorators';
import { WorkerHost } from './hosts';
import { ProcessorDecoratorService } from './instrument/processor-decorator.service';
import { NestQueueOptions } from './interfaces/queue-options.interface';
import { NestWorkerOptions } from './interfaces/worker-options.interface';
export declare class BullExplorer implements OnApplicationShutdown {
    private readonly moduleRef;
    private readonly discoveryService;
    private readonly metadataAccessor;
    private readonly metadataScanner;
    private readonly processorDecoratorService;
    private static _workerClass;
    private readonly logger;
    private readonly injector;
    private readonly workers;
    static set workerClass(cls: Type);
    constructor(moduleRef: ModuleRef, discoveryService: DiscoveryService, metadataAccessor: BullMetadataAccessor, metadataScanner: MetadataScanner, processorDecoratorService: ProcessorDecoratorService);
    onApplicationShutdown(signal?: string): Promise<void[]>;
    register(): void;
    registerWorkers(): void;
    getQueueOptions(queueToken: string, queueName: string, configKey?: string): NestQueueOptions;
    getFlowProducerOptions(flowProducerToken: string, name: string, configKey?: string): {};
    handleProcessor<T extends WorkerHost>(instance: T, queueName: string, queueOpts: NestQueueOptions, moduleRef: Module, isRequestScoped: boolean, options?: NestWorkerOptions): void;
    registerWorkerEventListeners(wrapper: InstanceWrapper): void;
    handleWorkerEvents(key: string, wrapper: InstanceWrapper, options: OnWorkerEventMetadata): void;
    registerQueueEventListeners(): void;
    handleQueueEvents(key: string, wrapper: InstanceWrapper, queueEventsInstance: QueueEvents, options: OnQueueEventMetadata): void;
}
//# sourceMappingURL=bull.explorer.d.ts.map