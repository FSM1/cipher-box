"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setGlobalAnalytics = exports.setGlobalAnalyticsKey = exports.getGlobalAnalytics = void 0;
/**
 * Stores the global window analytics key
 */
var _globalAnalyticsKey = 'analytics';
/**
 * Gets the global analytics/buffer
 * @param key name of the window property where the buffer is stored (default: analytics)
 * @returns AnalyticsSnippet
 */
function getGlobalAnalytics() {
    return window[_globalAnalyticsKey];
}
exports.getGlobalAnalytics = getGlobalAnalytics;
/**
 * Replaces the global window key for the analytics/buffer object
 * @param key key name
 */
function setGlobalAnalyticsKey(key) {
    _globalAnalyticsKey = key;
}
exports.setGlobalAnalyticsKey = setGlobalAnalyticsKey;
/**
 * Sets the global analytics object
 * @param analytics analytics snippet
 */
function setGlobalAnalytics(analytics) {
    ;
    window[_globalAnalyticsKey] = analytics;
}
exports.setGlobalAnalytics = setGlobalAnalytics;
//# sourceMappingURL=global-analytics-helper.js.map