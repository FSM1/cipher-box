import { __awaiter, __extends, __generator } from "tslib";
import { PersistedPriorityQueue } from '../../lib/priority-queue/persisted';
import { CoreEventQueue } from '@segment/analytics-core';
import { isOffline } from '../connection';
var EventQueue = /** @class */ (function (_super) {
    __extends(EventQueue, _super);
    function EventQueue(nameOrQueue) {
        return _super.call(this, typeof nameOrQueue === 'string'
            ? new PersistedPriorityQueue(4, nameOrQueue)
            : nameOrQueue) || this;
    }
    EventQueue.prototype.flush = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                if (isOffline())
                    return [2 /*return*/, []];
                return [2 /*return*/, _super.prototype.flush.call(this)];
            });
        });
    };
    return EventQueue;
}(CoreEventQueue));
export { EventQueue };
//# sourceMappingURL=event-queue.js.map