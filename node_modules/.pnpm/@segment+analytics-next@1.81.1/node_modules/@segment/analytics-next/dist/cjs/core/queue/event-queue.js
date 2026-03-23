"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EventQueue = void 0;
var tslib_1 = require("tslib");
var persisted_1 = require("../../lib/priority-queue/persisted");
var analytics_core_1 = require("@segment/analytics-core");
var connection_1 = require("../connection");
var EventQueue = /** @class */ (function (_super) {
    tslib_1.__extends(EventQueue, _super);
    function EventQueue(nameOrQueue) {
        return _super.call(this, typeof nameOrQueue === 'string'
            ? new persisted_1.PersistedPriorityQueue(4, nameOrQueue)
            : nameOrQueue) || this;
    }
    EventQueue.prototype.flush = function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            return tslib_1.__generator(this, function (_a) {
                if ((0, connection_1.isOffline)())
                    return [2 /*return*/, []];
                return [2 /*return*/, _super.prototype.flush.call(this)];
            });
        });
    };
    return EventQueue;
}(analytics_core_1.CoreEventQueue));
exports.EventQueue = EventQueue;
//# sourceMappingURL=event-queue.js.map