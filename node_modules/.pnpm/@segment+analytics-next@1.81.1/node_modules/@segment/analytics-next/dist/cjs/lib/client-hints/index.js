"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.clientHints = void 0;
var tslib_1 = require("tslib");
function clientHints(hints) {
    return tslib_1.__awaiter(this, void 0, void 0, function () {
        var userAgentData;
        return tslib_1.__generator(this, function (_a) {
            userAgentData = navigator.userAgentData;
            if (!userAgentData)
                return [2 /*return*/, undefined];
            if (!hints)
                return [2 /*return*/, userAgentData.toJSON()];
            return [2 /*return*/, userAgentData
                    .getHighEntropyValues(hints)
                    .catch(function () { return userAgentData.toJSON(); })];
        });
    });
}
exports.clientHints = clientHints;
//# sourceMappingURL=index.js.map