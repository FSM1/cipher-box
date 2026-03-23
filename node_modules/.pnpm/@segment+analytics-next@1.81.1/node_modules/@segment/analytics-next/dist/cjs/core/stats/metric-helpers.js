"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recordIntegrationMetric = void 0;
function recordIntegrationMetric(ctx, _a) {
    var methodName = _a.methodName, integrationName = _a.integrationName, type = _a.type, _b = _a.didError, didError = _b === void 0 ? false : _b;
    ctx.stats.increment("analytics_js.integration.invoke".concat(didError ? '.error' : ''), 1, [
        "method:".concat(methodName),
        "integration_name:".concat(integrationName),
        "type:".concat(type),
    ]);
}
exports.recordIntegrationMetric = recordIntegrationMetric;
//# sourceMappingURL=metric-helpers.js.map