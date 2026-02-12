type CSPErrorEvent = SecurityPolicyViolationEvent & {
    disposition?: 'enforce' | 'report';
};
export declare const isAnalyticsCSPError: (e: CSPErrorEvent) => boolean;
export declare function loadAjsClassicFallback(): Promise<void>;
export {};
//# sourceMappingURL=csp-detection.d.ts.map