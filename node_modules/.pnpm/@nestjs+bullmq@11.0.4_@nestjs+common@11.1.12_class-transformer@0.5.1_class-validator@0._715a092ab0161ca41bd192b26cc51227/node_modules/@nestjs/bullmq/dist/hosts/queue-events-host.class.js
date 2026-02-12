"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QueueEventsHost = void 0;
class QueueEventsHost {
    get queueEvents() {
        if (!this._queueEvents) {
            throw new Error('"QueueEvents" class has not yet been initialized. Make sure to interact with queue events instances after the "onModuleInit" lifecycle hook is triggered, for example, in the "onApplicationBootstrap" hook, or if "manualRegistration" is set to true make sure to call "BullRegistrar.register()"');
        }
        return this._queueEvents;
    }
    onApplicationShutdown(signal) {
        return this._queueEvents?.close();
    }
}
exports.QueueEventsHost = QueueEventsHost;
