import { DynamicModule, Type } from '@nestjs/common';
import { BullRootModuleOptions, RegisterFlowProducerAsyncOptions, RegisterFlowProducerOptions, SharedBullAsyncConfiguration } from './interfaces';
import { RegisterQueueAsyncOptions, RegisterQueueOptions } from './interfaces/register-queue-options.interface';
/**
 * @publicApi
 */
export declare class BullModule {
    private static _queueClass;
    private static _flowProducerClass;
    private static _workerClass;
    private static coreModuleDefinition;
    /**
     * Class to be used to create Bull queues.
     * This configuration property can be used to instruct the "@nestjs/bullmq"
     * package to use, for example, "QueuePro" class (from "BullMQ Pro").
     * @default Queue
     */
    static set queueClass(cls: Type);
    /**
     * Class to be used to create Bull flow producers.
     * This configuration property can be used to instruct the "@nestjs/bullmq"
     * package to use, for example, "FlowProducerPro" class (from "BullMQ Pro").
     * @default FlowProducer
     */
    static set flowProducerClass(cls: Type);
    /**
     * Class to be used to create Bull workers.
     * This configuration property can be used to instruct the "@nestjs/bullmq"
     * package to use, for example, "WorkerPro" class (from "BullMQ Pro").
     * @default Worker
     */
    static set workerClass(cls: Type);
    /**
     * Registers a globally available configuration for all queues.
     *
     * @param bullConfig shared bull configuration object
     */
    static forRoot(bullConfig: BullRootModuleOptions): DynamicModule;
    /**
     * Registers a globally available configuration under a specified "configKey".
     *
     * @param configKey a key under which the configuration should be available
     * @param sharedBullConfig shared bull configuration object
     */
    static forRoot(configKey: string, bullConfig: BullRootModuleOptions): DynamicModule;
    /**
     * Registers a globally available configuration for all queues.
     *
     * @param asyncBullConfig shared bull configuration async factory
     */
    static forRootAsync(asyncBullConfig: SharedBullAsyncConfiguration): DynamicModule;
    /**
     * Registers a globally available configuration under a specified "configKey".
     *
     * @param configKey a key under which the configuration should be available
     * @param asyncBullConfig shared bull configuration async factory
     */
    static forRootAsync(configKey: string, asyncBullConfig: SharedBullAsyncConfiguration): DynamicModule;
    static registerQueue(...options: RegisterQueueOptions[]): DynamicModule;
    static registerQueueAsync(...options: RegisterQueueAsyncOptions[]): DynamicModule;
    private static createAsyncProviders;
    private static createAsyncOptionsProvider;
    static registerFlowProducer(...options: RegisterFlowProducerOptions[]): DynamicModule;
    static registerFlowProducerAsync(...options: RegisterFlowProducerAsyncOptions[]): DynamicModule;
    private static createAsyncFlowProducerProviders;
    private static createAsyncFlowProducerOptionsProvider;
    private static createAsyncSharedConfigurationProviders;
    private static createAsyncSharedConfigurationProvider;
    private static getUniqImports;
}
//# sourceMappingURL=bull.module.d.ts.map