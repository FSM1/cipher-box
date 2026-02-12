import { type GetBlockTransactionCountErrorType, type GetBlockTransactionCountParameters, type GetBlockTransactionCountReturnType } from '../actions/getBlockTransactionCount.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { ExactPartial, UnionCompute } from '../types/utils.js';
export type GetBlockTransactionCountOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetBlockTransactionCountData> = UnionCompute<ExactPartial<GetBlockTransactionCountParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetBlockTransactionCountQueryFnData, GetBlockTransactionCountErrorType, selectData, GetBlockTransactionCountQueryKey<config, chainId>>;
export declare function getBlockTransactionCountQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetBlockTransactionCountData>(config: config, options?: GetBlockTransactionCountOptions<config, chainId, selectData>): GetBlockTransactionCountQueryOptions<config, chainId, selectData>;
export type GetBlockTransactionCountQueryFnData = GetBlockTransactionCountReturnType;
export type GetBlockTransactionCountData = GetBlockTransactionCountQueryFnData;
export declare function getBlockTransactionCountQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: UnionCompute<ExactPartial<GetBlockTransactionCountParameters<config, chainId>> & ScopeKeyParameter>): readonly ["blockTransactionCount", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    blockHash?: `0x${string}` | undefined;
    blockNumber?: bigint | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetBlockTransactionCountQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getBlockTransactionCountQueryKey<config, chainId>>;
export type GetBlockTransactionCountQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetBlockTransactionCountData> = QueryOptions<GetBlockTransactionCountQueryFnData, GetBlockTransactionCountErrorType, selectData, GetBlockTransactionCountQueryKey<config, chainId>>;
//# sourceMappingURL=getBlockTransactionCount.d.ts.map