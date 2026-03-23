import { __awaiter, __generator } from "tslib";
import { loadScript } from './load-script';
import { getLegacyAJSPath } from './parse-cdn';
export var isAnalyticsCSPError = function (e) {
    return e.disposition !== 'report' && e.blockedURI.includes('cdn.segment');
};
export function loadAjsClassicFallback() {
    return __awaiter(this, void 0, void 0, function () {
        var classicPath;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.warn('Your CSP policy is missing permissions required in order to run Analytics.js 2.0', 'https://segment.com/docs/connections/sources/catalog/libraries/website/javascript/upgrade-to-ajs2/#using-a-strict-content-security-policy-on-the-page');
                    console.warn('Reverting to Analytics.js 1.0');
                    classicPath = getLegacyAJSPath();
                    return [4 /*yield*/, loadScript(classicPath)];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
}
//# sourceMappingURL=csp-detection.js.map