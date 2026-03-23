import { type GetFeeHistoryErrorType, type GetFeeHistoryParameters, type GetFeeHistoryReturnType } from '../actions/getFeeHistory.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetFeeHistoryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetFeeHistoryData> = Compute<ExactPartial<GetFeeHistoryParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetFeeHistoryQueryFnData, GetFeeHistoryErrorType, selectData, GetFeeHistoryQueryKey<config, chainId>>;
export declare function getFeeHistoryQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetFeeHistoryData>(config: config, options?: GetFeeHistoryOptions<config, chainId, selectData>): GetFeeHistoryQueryOptions<config, chainId, selectData>;
export type GetFeeHistoryQueryFnData = GetFeeHistoryReturnType;
export type GetFeeHistoryData = GetFeeHistoryQueryFnData;
export declare function getFeeHistoryQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<GetFeeHistoryParameters<config, chainId>> & ScopeKeyParameter>): readonly ["feeHistory", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    blockNumber?: bigint | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    blockCount?: number | undefined;
    rewardPercentiles?: number[] | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetFeeHistoryQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getFeeHistoryQueryKey<config, chainId>>;
export type GetFeeHistoryQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetFeeHistoryData> = QueryOptions<GetFeeHistoryQueryFnData, GetFeeHistoryErrorType, selectData, GetFeeHistoryQueryKey<config, chainId>>;
//# sourceMappingURL=getFeeHistory.d.ts.map