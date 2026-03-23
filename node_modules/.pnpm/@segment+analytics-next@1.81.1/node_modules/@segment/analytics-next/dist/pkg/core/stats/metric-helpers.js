export function recordIntegrationMetric(ctx, _a) {
    var methodName = _a.methodName, integrationName = _a.integrationName, type = _a.type, _b = _a.didError, didError = _b === void 0 ? false : _b;
    ctx.stats.increment("analytics_js.integration.invoke".concat(didError ? '.error' : ''), 1, [
        "method:".concat(methodName),
        "integration_name:".concat(integrationName),
        "type:".concat(type),
    ]);
}
//# sourceMappingURL=metric-helpers.js.map