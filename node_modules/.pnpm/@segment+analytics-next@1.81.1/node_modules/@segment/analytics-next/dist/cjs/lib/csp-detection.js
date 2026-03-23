"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadAjsClassicFallback = exports.isAnalyticsCSPError = void 0;
var tslib_1 = require("tslib");
var load_script_1 = require("./load-script");
var parse_cdn_1 = require("./parse-cdn");
var isAnalyticsCSPError = function (e) {
    return e.disposition !== 'report' && e.blockedURI.includes('cdn.segment');
};
exports.isAnalyticsCSPError = isAnalyticsCSPError;
function loadAjsClassicFallback() {
    return tslib_1.__awaiter(this, void 0, void 0, function () {
        var classicPath;
        return tslib_1.__generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    console.warn('Your CSP policy is missing permissions required in order to run Analytics.js 2.0', 'https://segment.com/docs/connections/sources/catalog/libraries/website/javascript/upgrade-to-ajs2/#using-a-strict-content-security-policy-on-the-page');
                    console.warn('Reverting to Analytics.js 1.0');
                    classicPath = (0, parse_cdn_1.getLegacyAJSPath)();
                    return [4 /*yield*/, (0, load_script_1.loadScript)(classicPath)];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
}
exports.loadAjsClassicFallback = loadAjsClassicFallback;
//# sourceMappingURL=csp-detection.js.map