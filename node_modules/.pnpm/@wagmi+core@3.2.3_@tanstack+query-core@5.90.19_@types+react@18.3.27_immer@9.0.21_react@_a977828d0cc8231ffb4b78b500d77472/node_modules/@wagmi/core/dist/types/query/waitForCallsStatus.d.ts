import { type WaitForCallsStatusErrorType, type WaitForCallsStatusParameters, type WaitForCallsStatusReturnType } from '../actions/waitForCallsStatus.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type WaitForCallsStatusOptions<selectData = WaitForCallsStatusData> = Compute<ExactPartial<WaitForCallsStatusParameters> & ScopeKeyParameter> & QueryParameter<WaitForCallsStatusQueryFnData, WaitForCallsStatusErrorType, selectData, WaitForCallsStatusQueryKey>;
export declare function waitForCallsStatusQueryOptions<config extends Config, selectData = WaitForCallsStatusData>(config: config, options: WaitForCallsStatusOptions<selectData>): WaitForCallsStatusQueryOptions<selectData>;
export type WaitForCallsStatusQueryFnData = WaitForCallsStatusReturnType;
export type WaitForCallsStatusData = WaitForCallsStatusQueryFnData;
export declare function waitForCallsStatusQueryKey(options?: Compute<ExactPartial<WaitForCallsStatusParameters> & ScopeKeyParameter>): readonly ["callsStatus", {
    status?: ((parameters: import("viem").GetCallsStatusReturnType) => boolean) | undefined | undefined;
    pollingInterval?: number | undefined | undefined;
    id?: string | undefined;
    retryCount?: number | undefined;
    timeout?: number | undefined | undefined;
    retryDelay?: number | ((config: {
        count: number;
        error: Error;
    }) => number) | undefined;
    throwOnFailure?: boolean | undefined | undefined;
    scopeKey?: string | undefined | undefined;
    connectorUid?: string | undefined;
}];
export type WaitForCallsStatusQueryKey = ReturnType<typeof waitForCallsStatusQueryKey>;
export type WaitForCallsStatusQueryOptions<selectData = WaitForCallsStatusData> = QueryOptions<WaitForCallsStatusQueryFnData, WaitForCallsStatusErrorType, selectData, WaitForCallsStatusQueryKey>;
//# sourceMappingURL=waitForCallsStatus.d.ts.map