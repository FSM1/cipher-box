"use strict";
var BullExplorer_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.BullExplorer = void 0;
const tslib_1 = require("tslib");
const bull_shared_1 = require("@nestjs/bull-shared");
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const injector_1 = require("@nestjs/core/injector/injector");
const request_constants_1 = require("@nestjs/core/router/request/request-constants");
const bullmq_1 = require("bullmq");
const bull_metadata_accessor_1 = require("./bull-metadata.accessor");
const bull_messages_1 = require("./bull.messages");
const errors_1 = require("./errors");
const hosts_1 = require("./hosts");
const processor_decorator_service_1 = require("./instrument/processor-decorator.service");
const get_shared_config_token_util_1 = require("./utils/get-shared-config-token.util");
let BullExplorer = BullExplorer_1 = class BullExplorer {
    static set workerClass(cls) {
        this._workerClass = cls;
    }
    constructor(moduleRef, discoveryService, metadataAccessor, metadataScanner, processorDecoratorService) {
        this.moduleRef = moduleRef;
        this.discoveryService = discoveryService;
        this.metadataAccessor = metadataAccessor;
        this.metadataScanner = metadataScanner;
        this.processorDecoratorService = processorDecoratorService;
        this.logger = new common_1.Logger('BullModule');
        this.injector = new injector_1.Injector();
        this.workers = [];
    }
    onApplicationShutdown(signal) {
        return Promise.all(this.workers.map((worker) => worker.close()));
    }
    register() {
        this.registerWorkers();
        this.registerQueueEventListeners();
    }
    registerWorkers() {
        const processors = this.discoveryService
            .getProviders()
            .filter((wrapper) => this.metadataAccessor.isProcessor(
        // NOTE: Regarding the ternary statement below,
        // - The condition `!wrapper.metatype` is because when we use `useValue`
        // the value of `wrapper.metatype` will be `null`.
        // - The condition `wrapper.inject` is needed here because when we use
        // `useFactory`, the value of `wrapper.metatype` will be the supplied
        // factory function.
        // For both cases, we should use `wrapper.instance.constructor` instead
        // of `wrapper.metatype` to resolve processor's class properly.
        // But since calling `wrapper.instance` could degrade overall performance
        // we must defer it as much we can. But there's no other way to grab the
        // right class that could be annotated with `@Processor()` decorator
        // without using this property.
        !wrapper.metatype || wrapper.inject
            ? wrapper.instance?.constructor
            : wrapper.metatype));
        processors.forEach((wrapper) => {
            const { instance, metatype } = wrapper;
            const isRequestScoped = !wrapper.isDependencyTreeStatic();
            const { name: queueName, configKey } = this.metadataAccessor.getProcessorMetadata(
            // NOTE: We are relying on `instance.constructor` to properly support
            // `useValue` and `useFactory` providers besides `useClass`.
            instance.constructor || metatype);
            const queueToken = (0, bull_shared_1.getQueueToken)(queueName);
            const queueOpts = this.getQueueOptions(queueToken, queueName, configKey);
            if (!(instance instanceof hosts_1.WorkerHost)) {
                throw new errors_1.InvalidProcessorClassError(instance.constructor?.name);
            }
            else {
                const workerOptions = this.metadataAccessor.getWorkerOptionsMetadata(instance.constructor);
                this.handleProcessor(instance, queueName, queueOpts, wrapper.host, isRequestScoped, workerOptions);
            }
            this.registerWorkerEventListeners(wrapper);
        });
    }
    getQueueOptions(queueToken, queueName, configKey) {
        try {
            const queueRef = this.moduleRef.get(queueToken, { strict: false });
            return (queueRef.opts ?? {});
        }
        catch (err) {
            const sharedConfigToken = (0, get_shared_config_token_util_1.getSharedConfigToken)(configKey);
            try {
                return this.moduleRef.get(sharedConfigToken, {
                    strict: false,
                });
            }
            catch (err) {
                this.logger.error((0, bull_shared_1.NO_QUEUE_FOUND)(queueName));
                throw err;
            }
        }
    }
    getFlowProducerOptions(flowProducerToken, name, configKey) {
        try {
            const flowProducerRef = this.moduleRef.get(flowProducerToken, { strict: false });
            return flowProducerRef.opts ?? {};
        }
        catch (err) {
            const sharedConfigToken = (0, get_shared_config_token_util_1.getSharedConfigToken)(configKey);
            try {
                return this.moduleRef.get(sharedConfigToken, {
                    strict: false,
                });
            }
            catch (err) {
                this.logger.error((0, bull_messages_1.NO_FLOW_PRODUCER_FOUND)(name));
                throw err;
            }
        }
    }
    handleProcessor(instance, queueName, queueOpts, moduleRef, isRequestScoped, options = {}) {
        const methodKey = 'process';
        let processor;
        if (isRequestScoped) {
            processor = async (...args) => {
                const jobRef = args[0];
                const contextId = core_1.ContextIdFactory.getByRequest(jobRef);
                if (this.moduleRef.registerRequestByContextId &&
                    !contextId[request_constants_1.REQUEST_CONTEXT_ID]) {
                    // Additional condition to prevent breaking changes in
                    // applications that use @nestjs/bull older than v7.4.0.
                    this.moduleRef.registerRequestByContextId(jobRef, contextId);
                }
                const contextInstance = await this.injector.loadPerContext(instance, moduleRef, moduleRef.providers, contextId);
                const processor = contextInstance[methodKey].bind(contextInstance);
                return this.processorDecoratorService.decorate(processor)(...args);
            };
        }
        else {
            processor = instance[methodKey].bind(instance);
            processor = this.processorDecoratorService.decorate(processor);
        }
        const worker = new BullExplorer_1._workerClass(queueName, processor, {
            connection: queueOpts.connection,
            sharedConnection: queueOpts.sharedConnection,
            prefix: queueOpts.prefix,
            telemetry: queueOpts.telemetry,
            ...options,
        });
        instance._worker = worker;
        this.workers.push(worker);
    }
    registerWorkerEventListeners(wrapper) {
        const { instance } = wrapper;
        this.metadataScanner.scanFromPrototype(instance, Object.getPrototypeOf(instance), (key) => {
            const workerEventHandlerMetadata = this.metadataAccessor.getOnWorkerEventMetadata(instance[key]);
            if (workerEventHandlerMetadata) {
                this.handleWorkerEvents(key, wrapper, workerEventHandlerMetadata);
            }
        });
    }
    handleWorkerEvents(key, wrapper, options) {
        const { instance } = wrapper;
        if (!wrapper.isDependencyTreeStatic()) {
            this.logger.warn(`Warning! "${wrapper.name}" class is request-scoped and it defines an event listener ("${wrapper.name}#${key}"). Since event listeners cannot be registered on scoped providers, this handler will be ignored.`);
            return;
        }
        instance.worker.on(options.eventName, instance[key].bind(instance));
    }
    registerQueueEventListeners() {
        const eventListeners = this.discoveryService
            .getProviders()
            .filter((wrapper) => this.metadataAccessor.isQueueEventsListener(
        // NOTE: Regarding the ternary statement below,
        // - The condition `!wrapper.metatype` is because when we use `useValue`
        // the value of `wrapper.metatype` will be `null`.
        // - The condition `wrapper.inject` is needed here because when we use
        // `useFactory`, the value of `wrapper.metatype` will be the supplied
        // factory function.
        // For both cases, we should use `wrapper.instance.constructor` instead
        // of `wrapper.metatype` to resolve processor's class properly.
        // But since calling `wrapper.instance` could degrade overall performance
        // we must defer it as much we can. But there's no other way to grab the
        // right class that could be annotated with `@Processor()` decorator
        // without using this property.
        !wrapper.metatype || wrapper.inject
            ? wrapper.instance?.constructor
            : wrapper.metatype));
        eventListeners.forEach((wrapper) => {
            const { instance, metatype } = wrapper;
            if (!wrapper.isDependencyTreeStatic()) {
                this.logger.warn(`Warning! "${wrapper.name}" class is request-scoped and it is flagged as an event listener. Since event listeners cannot be registered on scoped providers, this handler will be ignored.`);
                return;
            }
            const { queueName, queueEventsOptions } = this.metadataAccessor.getQueueEventsListenerMetadata(
            // NOTE: We are relying on `instance.constructor` to properly support
            // `useValue` and `useFactory` providers besides `useClass`.
            instance.constructor || metatype);
            const queueToken = (0, bull_shared_1.getQueueToken)(queueName);
            const queueOpts = this.getQueueOptions(queueToken, queueName);
            if (!(instance instanceof hosts_1.QueueEventsHost)) {
                throw new errors_1.InvalidQueueEventsListenerClassError(instance.constructor?.name);
            }
            else {
                const queueEventsInstance = new bullmq_1.QueueEvents(queueName, {
                    connection: queueOpts.connection,
                    prefix: queueOpts.prefix,
                    sharedConnection: queueOpts.sharedConnection,
                    telemetry: queueOpts.telemetry,
                    ...queueEventsOptions,
                });
                instance._queueEvents = queueEventsInstance;
                this.metadataScanner.scanFromPrototype(instance, Object.getPrototypeOf(instance), (key) => {
                    const queueEventHandlerMetadata = this.metadataAccessor.getOnQueueEventMetadata(instance[key]);
                    if (queueEventHandlerMetadata) {
                        this.handleQueueEvents(key, wrapper, queueEventsInstance, queueEventHandlerMetadata);
                    }
                });
            }
        });
    }
    handleQueueEvents(key, wrapper, queueEventsInstance, options) {
        const { eventName } = options;
        const { instance } = wrapper;
        queueEventsInstance.on(eventName, instance[key].bind(instance));
    }
};
exports.BullExplorer = BullExplorer;
BullExplorer._workerClass = bullmq_1.Worker;
exports.BullExplorer = BullExplorer = BullExplorer_1 = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [core_1.ModuleRef,
        core_1.DiscoveryService,
        bull_metadata_accessor_1.BullMetadataAccessor,
        core_1.MetadataScanner,
        processor_decorator_service_1.ProcessorDecoratorService])
], BullExplorer);
