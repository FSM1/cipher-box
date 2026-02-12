/**
 * Stores the global window analytics key
 */
var _globalAnalyticsKey = 'analytics';
/**
 * Gets the global analytics/buffer
 * @param key name of the window property where the buffer is stored (default: analytics)
 * @returns AnalyticsSnippet
 */
export function getGlobalAnalytics() {
    return window[_globalAnalyticsKey];
}
/**
 * Replaces the global window key for the analytics/buffer object
 * @param key key name
 */
export function setGlobalAnalyticsKey(key) {
    _globalAnalyticsKey = key;
}
/**
 * Sets the global analytics object
 * @param analytics analytics snippet
 */
export function setGlobalAnalytics(analytics) {
    ;
    window[_globalAnalyticsKey] = analytics;
}
//# sourceMappingURL=global-analytics-helper.js.map