import { Job, Worker } from 'bullmq';
export declare abstract class WorkerHost<T extends Worker = Worker> {
    private readonly _worker;
    get worker(): T;
    abstract process(job: Job, token?: string): Promise<any>;
}
//# sourceMappingURL=worker-host.class.d.ts.map