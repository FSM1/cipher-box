import { type GetBlockNumberErrorType, type GetBlockNumberParameters, type GetBlockNumberReturnType } from '../actions/getBlockNumber.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetBlockNumberOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetBlockNumberData> = Compute<ExactPartial<GetBlockNumberParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetBlockNumberQueryFnData, GetBlockNumberErrorType, selectData, GetBlockNumberQueryKey<config, chainId>>;
export declare function getBlockNumberQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetBlockNumberData>(config: config, options?: GetBlockNumberOptions<config, chainId, selectData>): GetBlockNumberQueryOptions<config, chainId, selectData>;
export type GetBlockNumberQueryFnData = GetBlockNumberReturnType;
export type GetBlockNumberData = GetBlockNumberQueryFnData;
export declare function getBlockNumberQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<GetBlockNumberParameters<config, chainId>> & ScopeKeyParameter>): readonly ["blockNumber", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    cacheTime?: number | undefined | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetBlockNumberQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getBlockNumberQueryKey<config, chainId>>;
export type GetBlockNumberQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetBlockNumberData> = QueryOptions<GetBlockNumberQueryFnData, GetBlockNumberErrorType, selectData, GetBlockNumberQueryKey<config, chainId>>;
//# sourceMappingURL=getBlockNumber.d.ts.map