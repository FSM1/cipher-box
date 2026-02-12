import { type GetCallsStatusErrorType, type GetCallsStatusParameters, type GetCallsStatusReturnType } from '../actions/getCallsStatus.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute } from '../types/utils.js';
export type GetCallsStatusOptions<selectData = GetCallsStatusData> = Compute<GetCallsStatusParameters & ScopeKeyParameter> & QueryParameter<GetCallsStatusQueryFnData, GetCallsStatusErrorType, selectData, GetCallsStatusQueryKey>;
export declare function getCallsStatusQueryOptions<config extends Config, selectData = GetCallsStatusData>(config: config, options: GetCallsStatusOptions<selectData>): GetCallsStatusQueryOptions<selectData>;
export type GetCallsStatusQueryFnData = GetCallsStatusReturnType;
export type GetCallsStatusData = GetCallsStatusQueryFnData;
export declare function getCallsStatusQueryKey(options: Compute<GetCallsStatusParameters & ScopeKeyParameter>): readonly ["callsStatus", {
    id: string;
    scopeKey?: string | undefined | undefined;
    connectorUid?: string | undefined;
}];
export type GetCallsStatusQueryKey = ReturnType<typeof getCallsStatusQueryKey>;
export type GetCallsStatusQueryOptions<selectData = GetCallsStatusData> = QueryOptions<GetCallsStatusQueryFnData, GetCallsStatusErrorType, selectData, GetCallsStatusQueryKey>;
//# sourceMappingURL=getCallsStatus.d.ts.map