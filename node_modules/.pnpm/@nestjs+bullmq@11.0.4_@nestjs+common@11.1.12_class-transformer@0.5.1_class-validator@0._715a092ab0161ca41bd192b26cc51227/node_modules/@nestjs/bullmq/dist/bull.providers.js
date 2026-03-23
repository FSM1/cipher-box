"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createQueueOptionProviders = createQueueOptionProviders;
exports.createFlowProducerOptionProviders = createFlowProducerOptionProviders;
exports.createQueueProviders = createQueueProviders;
exports.createFlowProducerProviders = createFlowProducerProviders;
const bull_shared_1 = require("@nestjs/bull-shared");
const common_1 = require("@nestjs/common");
const utils_1 = require("./utils");
const helpers_1 = require("./utils/helpers");
function createQueueAndWorkers(options, queueClass, workerClass) {
    const queueName = options.name ?? 'default';
    const queue = new queueClass(queueName, options);
    let workerRefs = [];
    if (options.processors) {
        workerRefs = options.processors.map((processor) => {
            if ((0, helpers_1.isAdvancedProcessor)(processor)) {
                const { callback, ...processorOptions } = processor;
                return new workerClass(queueName, callback, {
                    connection: options.connection,
                    sharedConnection: options.sharedConnection,
                    prefix: options.prefix,
                    ...processorOptions,
                });
            }
            else if ((0, helpers_1.isAdvancedSeparateProcessor)(processor)) {
                const { path, ...processorOptions } = processor;
                return new workerClass(queueName, path, {
                    connection: options.connection,
                    sharedConnection: options.sharedConnection,
                    prefix: options.prefix,
                    ...processorOptions,
                });
            }
            else if ((0, helpers_1.isSeparateProcessor)(processor)) {
                return new workerClass(queueName, processor, {
                    connection: options.connection,
                    sharedConnection: options.sharedConnection,
                    prefix: options.prefix,
                });
            }
            else if ((0, helpers_1.isProcessorCallback)(processor)) {
                return new workerClass(queueName, processor, {
                    connection: options.connection,
                    sharedConnection: options.sharedConnection,
                    prefix: options.prefix,
                });
            }
        });
    }
    queue.onApplicationShutdown =
        async function () {
            const closeWorkers = workerRefs.map((worker) => worker.close());
            await Promise.all(closeWorkers);
            await this.close();
            if (options.forceDisconnectOnShutdown) {
                if (this.connection?.status !== 'closed' && this.disconnect) {
                    return this.disconnect();
                }
            }
        };
    return queue;
}
function createFlowProducers(options, flowProducerClass) {
    const flowProducer = new flowProducerClass(options);
    flowProducer.onApplicationShutdown =
        async function () {
            await this.close();
            if (options.forceDisconnectOnShutdown ?? true) {
                if (this.connection?.status !== 'closed' && this.disconnect) {
                    return this.disconnect();
                }
            }
        };
    return flowProducer;
}
function createQueueOptionProviders(options) {
    const providers = options.map((option) => {
        const optionalSharedConfigHolder = (0, bull_shared_1.createConditionalDepHolder)((0, utils_1.getSharedConfigToken)(option.configKey), utils_1.BULL_CONFIG_DEFAULT_TOKEN);
        return [
            optionalSharedConfigHolder,
            {
                provide: (0, utils_1.getQueueOptionsToken)(option.name),
                useFactory: (optionalDepHolder) => {
                    return {
                        ...optionalDepHolder.getDependencyRef(option.name),
                        ...option,
                    };
                },
                inject: [optionalSharedConfigHolder],
            },
        ];
    });
    return (0, common_1.flatten)(providers);
}
function createFlowProducerOptionProviders(options) {
    const providers = options.map((option) => {
        const optionalSharedConfigHolder = (0, bull_shared_1.createConditionalDepHolder)((0, utils_1.getSharedConfigToken)(option.configKey), utils_1.BULL_CONFIG_DEFAULT_TOKEN);
        return [
            optionalSharedConfigHolder,
            {
                provide: (0, utils_1.getFlowProducerOptionsToken)(option.name),
                useFactory: (optionalDepHolder) => {
                    return {
                        ...optionalDepHolder.getDependencyRef(option.name),
                        ...option,
                    };
                },
                inject: [optionalSharedConfigHolder],
            },
        ];
    });
    return (0, common_1.flatten)(providers);
}
function createQueueProviders(options, queueClass, workerClass) {
    const queueProviders = options.map((item) => ({
        provide: (0, bull_shared_1.getQueueToken)(item.name),
        useFactory: (queueOptions) => {
            const queueName = queueOptions.name || item.name;
            return createQueueAndWorkers({ ...queueOptions, name: queueName }, queueClass, workerClass);
        },
        inject: [(0, utils_1.getQueueOptionsToken)(item.name)],
    }));
    return queueProviders;
}
function createFlowProducerProviders(options, flowProducerClass) {
    const flowProducerProviders = options.map((item) => ({
        provide: (0, utils_1.getFlowProducerToken)(item.name),
        useFactory: (flowProducerOptions) => {
            const flowProducerName = flowProducerOptions.name || item.name;
            return createFlowProducers({ ...flowProducerOptions, name: flowProducerName }, flowProducerClass);
        },
        inject: [(0, utils_1.getFlowProducerOptionsToken)(item.name)],
    }));
    return flowProducerProviders;
}
