import { type EstimateMaxPriorityFeePerGasErrorType, type EstimateMaxPriorityFeePerGasParameters, type EstimateMaxPriorityFeePerGasReturnType } from '../actions/estimateMaxPriorityFeePerGas.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type EstimateMaxPriorityFeePerGasOptions<config extends Config, selectData = EstimateMaxPriorityFeePerGasData> = Compute<ExactPartial<EstimateMaxPriorityFeePerGasParameters<config>> & ScopeKeyParameter> & QueryParameter<EstimateMaxPriorityFeePerGasQueryFnData, EstimateMaxPriorityFeePerGasErrorType, selectData, EstimateMaxPriorityFeePerGasQueryKey<config>>;
export declare function estimateMaxPriorityFeePerGasQueryOptions<config extends Config, selectData = EstimateMaxPriorityFeePerGasData>(config: config, options?: EstimateMaxPriorityFeePerGasOptions<config, selectData>): EstimateMaxPriorityFeePerGasQueryOptions<config, selectData>;
export type EstimateMaxPriorityFeePerGasQueryFnData = EstimateMaxPriorityFeePerGasReturnType;
export type EstimateMaxPriorityFeePerGasData = EstimateMaxPriorityFeePerGasQueryFnData;
export declare function estimateMaxPriorityFeePerGasQueryKey<config extends Config>(options?: Compute<ExactPartial<EstimateMaxPriorityFeePerGasParameters<config>> & ScopeKeyParameter>): readonly ["estimateMaxPriorityFeePerGas", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type EstimateMaxPriorityFeePerGasQueryKey<config extends Config> = ReturnType<typeof estimateMaxPriorityFeePerGasQueryKey<config>>;
export type EstimateMaxPriorityFeePerGasQueryOptions<config extends Config, selectData = EstimateMaxPriorityFeePerGasData> = QueryOptions<EstimateMaxPriorityFeePerGasQueryFnData, EstimateMaxPriorityFeePerGasErrorType, selectData, EstimateMaxPriorityFeePerGasQueryKey<config>>;
//# sourceMappingURL=estimateMaxPriorityFeePerGas.d.ts.map