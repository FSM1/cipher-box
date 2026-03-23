import { AnalyticsSnippet } from '../browser/standalone-interface';
/**
 * Gets the global analytics/buffer
 * @param key name of the window property where the buffer is stored (default: analytics)
 * @returns AnalyticsSnippet
 */
export declare function getGlobalAnalytics(): AnalyticsSnippet | undefined;
/**
 * Replaces the global window key for the analytics/buffer object
 * @param key key name
 */
export declare function setGlobalAnalyticsKey(key: string): void;
/**
 * Sets the global analytics object
 * @param analytics analytics snippet
 */
export declare function setGlobalAnalytics(analytics: AnalyticsSnippet): void;
//# sourceMappingURL=global-analytics-helper.d.ts.map