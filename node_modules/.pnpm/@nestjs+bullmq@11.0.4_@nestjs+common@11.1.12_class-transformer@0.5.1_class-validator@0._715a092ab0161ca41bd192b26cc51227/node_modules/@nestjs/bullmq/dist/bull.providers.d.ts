import { Provider, Type } from '@nestjs/common';
import { FlowProducer, Queue, Worker } from 'bullmq';
import { RegisterFlowProducerOptions } from './interfaces';
import { RegisterQueueOptions } from './interfaces/register-queue-options.interface';
export declare function createQueueOptionProviders(options: RegisterQueueOptions[]): Provider[];
export declare function createFlowProducerOptionProviders(options: RegisterFlowProducerOptions[]): Provider[];
export declare function createQueueProviders<TQueue = Queue, TWorker extends Worker = Worker>(options: RegisterQueueOptions[], queueClass: Type<TQueue>, workerClass: Type<TWorker>): Provider[];
export declare function createFlowProducerProviders<TFlowProducer = FlowProducer>(options: RegisterFlowProducerOptions[], flowProducerClass: Type<TFlowProducer>): Provider[];
//# sourceMappingURL=bull.providers.d.ts.map