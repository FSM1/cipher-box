"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WorkerHost = void 0;
class WorkerHost {
    get worker() {
        if (!this._worker) {
            throw new Error('"Worker" has not yet been initialized. Make sure to interact with worker instances after the "onModuleInit" lifecycle hook is triggered for example, in the "onApplicationBootstrap" hook, or if "manualRegistration" is set to true make sure to call "BullRegistrar.register()"');
        }
        return this._worker;
    }
}
exports.WorkerHost = WorkerHost;
