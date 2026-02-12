import { __awaiter, __generator } from "tslib";
export function clientHints(hints) {
    return __awaiter(this, void 0, void 0, function () {
        var userAgentData;
        return __generator(this, function (_a) {
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
//# sourceMappingURL=index.js.map