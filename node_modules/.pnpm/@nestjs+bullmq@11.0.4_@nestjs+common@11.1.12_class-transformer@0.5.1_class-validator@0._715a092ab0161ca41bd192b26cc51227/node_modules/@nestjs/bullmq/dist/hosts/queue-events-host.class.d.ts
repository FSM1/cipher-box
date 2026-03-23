import { OnApplicationShutdown } from '@nestjs/common';
import { QueueEvents } from 'bullmq';
export declare abstract class QueueEventsHost<T extends QueueEvents = QueueEvents> implements OnApplicationShutdown {
    private _queueEvents;
    get queueEvents(): T;
    onApplicationShutdown(signal?: string): Promise<void>;
}
//# sourceMappingURL=queue-events-host.class.d.ts.map