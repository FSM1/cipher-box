"use strict";
var BullModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.BullModule = void 0;
const tslib_1 = require("tslib");
const bull_shared_1 = require("@nestjs/bull-shared");
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const bullmq_1 = require("bullmq");
const bull_metadata_accessor_1 = require("./bull-metadata.accessor");
const bull_constants_1 = require("./bull.constants");
const bull_explorer_1 = require("./bull.explorer");
const bull_providers_1 = require("./bull.providers");
const bull_registrar_1 = require("./bull.registrar");
const processor_decorator_service_1 = require("./instrument/processor-decorator.service");
const utils_1 = require("./utils");
/**
 * @publicApi
 */
let BullModule = BullModule_1 = class BullModule {
    /**
     * Class to be used to create Bull queues.
     * This configuration property can be used to instruct the "@nestjs/bullmq"
     * package to use, for example, "QueuePro" class (from "BullMQ Pro").
     * @default Queue
     */
    static set queueClass(cls) {
        this._queueClass = cls;
    }
    /**
     * Class to be used to create Bull flow producers.
     * This configuration property can be used to instruct the "@nestjs/bullmq"
     * package to use, for example, "FlowProducerPro" class (from "BullMQ Pro").
     * @default FlowProducer
     */
    static set flowProducerClass(cls) {
        this._flowProducerClass = cls;
    }
    /**
     * Class to be used to create Bull workers.
     * This configuration property can be used to instruct the "@nestjs/bullmq"
     * package to use, for example, "WorkerPro" class (from "BullMQ Pro").
     * @default Worker
     */
    static set workerClass(cls) {
        bull_explorer_1.BullExplorer.workerClass = cls;
        this._workerClass = cls;
    }
    /**
     * Registers a globally available configuration for all queues
     * or using a specified "configKey" (if passed).
     *
     * @param keyOrConfig a key under which the configuration should be available or a bull configuration object
     * @param bullConfig bull configuration object
     */
    static forRoot(keyOrConfig, bullConfig) {
        const [configKey, sharedBullConfig] = typeof keyOrConfig === 'string'
            ? [keyOrConfig, bullConfig]
            : [undefined, keyOrConfig];
        const { extraOptions, ...config } = sharedBullConfig;
        const sharedBullConfigProvider = {
            provide: (0, utils_1.getSharedConfigToken)(configKey),
            useValue: config,
        };
        const extraOptionsProvider = {
            provide: bull_constants_1.BULL_EXTRA_OPTIONS_TOKEN,
            useValue: { ...extraOptions },
        };
        return {
            global: true,
            module: BullModule_1,
            providers: [sharedBullConfigProvider, extraOptionsProvider],
            exports: [sharedBullConfigProvider, extraOptionsProvider],
        };
    }
    /**
     * Registers a globally available configuration for all queues
     * or using a specified "configKey" (if passed).
     *
     * @param keyOrAsyncConfig a key under which the configuration should be available or a bull configuration object
     * @param asyncBullConfig shared bull configuration async factory
     */
    static forRootAsync(keyOrAsyncConfig, asyncBullConfig) {
        const [configKey, asyncSharedBullConfig] = typeof keyOrAsyncConfig === 'string'
            ? [keyOrAsyncConfig, asyncBullConfig]
            : [undefined, keyOrAsyncConfig];
        const imports = this.getUniqImports([asyncSharedBullConfig]);
        const providers = this.createAsyncSharedConfigurationProviders(configKey, asyncSharedBullConfig);
        return {
            global: true,
            module: BullModule_1,
            imports,
            providers: asyncSharedBullConfig.extraProviders
                ? [...providers, ...asyncSharedBullConfig.extraProviders]
                : providers,
            exports: providers,
        };
    }
    static registerQueue(...options) {
        const optionsArr = [].concat(options);
        const queueProviders = (0, bull_providers_1.createQueueProviders)(optionsArr, this._queueClass, this._workerClass);
        const queueOptionProviders = (0, bull_providers_1.createQueueOptionProviders)(optionsArr);
        return {
            module: BullModule_1,
            imports: [BullModule_1.coreModuleDefinition],
            providers: [...queueOptionProviders, ...queueProviders],
            exports: queueProviders,
        };
    }
    static registerQueueAsync(...options) {
        const optionsArr = [].concat(options);
        const queueProviders = (0, bull_providers_1.createQueueProviders)(optionsArr, this._queueClass, this._workerClass);
        const imports = this.getUniqImports(optionsArr);
        const asyncQueueOptionsProviders = options
            .map((queueOptions) => this.createAsyncProviders(queueOptions))
            .reduce((a, b) => a.concat(b), []);
        const extraProviders = options
            .map((queueOptions) => queueOptions.extraProviders)
            .filter((extraProviders) => extraProviders)
            .reduce((a, b) => a.concat(b), []);
        return {
            imports: imports.concat(BullModule_1.coreModuleDefinition),
            module: BullModule_1,
            providers: [
                ...asyncQueueOptionsProviders,
                ...queueProviders,
                ...extraProviders,
            ],
            exports: queueProviders,
        };
    }
    static createAsyncProviders(options) {
        const optionalSharedConfigHolder = (0, bull_shared_1.createConditionalDepHolder)((0, utils_1.getSharedConfigToken)(options.configKey), utils_1.BULL_CONFIG_DEFAULT_TOKEN);
        if (options.useExisting || options.useFactory) {
            return [
                optionalSharedConfigHolder,
                this.createAsyncOptionsProvider(options, optionalSharedConfigHolder),
            ];
        }
        if (!options.useClass) {
            // fallback to the "registerQueue" in case someone accidentally used the "registerQueueAsync" instead
            return (0, bull_providers_1.createQueueOptionProviders)([options]);
        }
        const useClass = options.useClass;
        return [
            optionalSharedConfigHolder,
            this.createAsyncOptionsProvider(options, optionalSharedConfigHolder),
            {
                provide: useClass,
                useClass,
            },
        ];
    }
    static createAsyncOptionsProvider(asyncOptions, optionalSharedConfigHolderRef) {
        if (asyncOptions.useFactory) {
            return {
                provide: (0, utils_1.getQueueOptionsToken)(asyncOptions.name),
                useFactory: async (optionalDepHolder, ...factoryArgs) => {
                    return {
                        ...optionalDepHolder.getDependencyRef(asyncOptions.name),
                        ...(await asyncOptions.useFactory(...factoryArgs)),
                    };
                },
                inject: [optionalSharedConfigHolderRef, ...(asyncOptions.inject || [])],
            };
        }
        // `as Type<BullOptionsFactory>` is a workaround for microsoft/TypeScript#31603
        const inject = [asyncOptions.useClass || asyncOptions.useExisting];
        return {
            provide: (0, utils_1.getQueueOptionsToken)(asyncOptions.name),
            useFactory: async (optionalDepHolder, optionsFactory) => {
                return {
                    ...optionalDepHolder.getDependencyRef(asyncOptions.name),
                    ...(await optionsFactory.createRegisterQueueOptions()),
                };
            },
            inject: [optionalSharedConfigHolderRef, ...inject],
        };
    }
    static registerFlowProducer(...options) {
        const optionsArr = [].concat(options);
        const flowProducerProviders = (0, bull_providers_1.createFlowProducerProviders)(optionsArr, this._flowProducerClass);
        const flowProducerOptionProviders = (0, bull_providers_1.createFlowProducerOptionProviders)(optionsArr);
        return {
            module: BullModule_1,
            imports: [BullModule_1.coreModuleDefinition],
            providers: [...flowProducerOptionProviders, ...flowProducerProviders],
            exports: flowProducerProviders,
        };
    }
    static registerFlowProducerAsync(...options) {
        const optionsArr = [].concat(options);
        const flowProducerProviders = (0, bull_providers_1.createFlowProducerProviders)(optionsArr, this._flowProducerClass);
        const imports = this.getUniqImports(optionsArr);
        const asyncFlowProducerOptionsProviders = options
            .map((flowProducerOptions) => this.createAsyncFlowProducerProviders(flowProducerOptions))
            .reduce((a, b) => a.concat(b), []);
        return {
            imports: imports.concat(BullModule_1.coreModuleDefinition),
            module: BullModule_1,
            providers: [
                ...asyncFlowProducerOptionsProviders,
                ...flowProducerProviders,
            ],
            exports: flowProducerProviders,
        };
    }
    static createAsyncFlowProducerProviders(options) {
        const optionalSharedConfigHolder = (0, bull_shared_1.createConditionalDepHolder)((0, utils_1.getSharedConfigToken)(options.configKey), utils_1.BULL_CONFIG_DEFAULT_TOKEN);
        if (options.useExisting || options.useFactory) {
            return [
                optionalSharedConfigHolder,
                this.createAsyncFlowProducerOptionsProvider(options, optionalSharedConfigHolder),
            ];
        }
        if (!options.useClass) {
            // fallback to the "registerFlowProducer" in case someone accidentally used the "registerFlowProducerAsync" instead
            return (0, bull_providers_1.createFlowProducerOptionProviders)([options]);
        }
        const useClass = options.useClass;
        return [
            optionalSharedConfigHolder,
            this.createAsyncFlowProducerOptionsProvider(options, optionalSharedConfigHolder),
            {
                provide: useClass,
                useClass,
            },
        ];
    }
    static createAsyncFlowProducerOptionsProvider(asyncOptions, optionalSharedConfigHolderRef) {
        if (asyncOptions.useFactory) {
            return {
                provide: (0, utils_1.getFlowProducerOptionsToken)(asyncOptions.name),
                useFactory: async (optionalDepHolder, ...factoryArgs) => {
                    return {
                        ...optionalDepHolder.getDependencyRef(asyncOptions.name),
                        ...(await asyncOptions.useFactory(...factoryArgs)),
                    };
                },
                inject: [optionalSharedConfigHolderRef, ...(asyncOptions.inject || [])],
            };
        }
        // `as Type<BullOptionsFactory>` is a workaround for microsoft/TypeScript#31603
        const inject = [asyncOptions.useClass || asyncOptions.useExisting];
        return {
            provide: (0, utils_1.getFlowProducerOptionsToken)(asyncOptions.name),
            useFactory: async (optionalDepHolder, optionsFactory) => {
                return {
                    ...optionalDepHolder.getDependencyRef(asyncOptions.name),
                    ...(await optionsFactory.createRegisterQueueOptions()),
                };
            },
            inject: [optionalSharedConfigHolderRef, ...inject],
        };
    }
    static createAsyncSharedConfigurationProviders(configKey, options) {
        const { extraOptions, ...config } = options;
        const extraOptionsProvider = {
            provide: bull_constants_1.BULL_EXTRA_OPTIONS_TOKEN,
            useValue: { ...extraOptions },
        };
        if (options.useExisting || options.useFactory) {
            return [
                this.createAsyncSharedConfigurationProvider(configKey, config),
                extraOptionsProvider,
            ];
        }
        const useClass = config.useClass;
        return [
            this.createAsyncSharedConfigurationProvider(configKey, config),
            extraOptionsProvider,
            {
                provide: useClass,
                useClass,
            },
        ];
    }
    static createAsyncSharedConfigurationProvider(configKey, options) {
        if (options.useFactory) {
            return {
                provide: (0, utils_1.getSharedConfigToken)(configKey),
                useFactory: options.useFactory,
                inject: options.inject || [],
            };
        }
        // `as Type<SharedBullConfigurationFactory>` is a workaround for microsoft/TypeScript#31603
        const inject = [options.useClass || options.useExisting];
        return {
            provide: (0, utils_1.getSharedConfigToken)(configKey),
            useFactory: async (optionsFactory) => optionsFactory.createSharedConfiguration(),
            inject,
        };
    }
    static getUniqImports(options) {
        return (options
            .map((option) => option.imports)
            .reduce((acc, i) => acc.concat(i || []), [])
            .filter((v, i, a) => a.indexOf(v) === i) || []);
    }
};
exports.BullModule = BullModule;
BullModule._queueClass = bullmq_1.Queue;
BullModule._flowProducerClass = bullmq_1.FlowProducer;
BullModule._workerClass = bullmq_1.Worker;
BullModule.coreModuleDefinition = {
    global: true,
    module: BullModule_1,
    imports: [core_1.DiscoveryModule],
    providers: [
        bull_explorer_1.BullExplorer,
        bull_metadata_accessor_1.BullMetadataAccessor,
        bull_registrar_1.BullRegistrar,
        processor_decorator_service_1.ProcessorDecoratorService,
    ],
    exports: [bull_registrar_1.BullRegistrar],
};
exports.BullModule = BullModule = BullModule_1 = tslib_1.__decorate([
    (0, common_1.Module)({})
], BullModule);
