import { type GetTransactionErrorType, type GetTransactionParameters, type GetTransactionReturnType } from '../actions/getTransaction.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetTransactionOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetTransactionData<config, chainId>> = Compute<ExactPartial<GetTransactionParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetTransactionQueryFnData<config, chainId>, GetTransactionErrorType, selectData, GetTransactionQueryKey<config, chainId>>;
export declare function getTransactionQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetTransactionData<config, chainId>>(config: config, options?: GetTransactionOptions<config, chainId, selectData>): GetTransactionQueryOptions<config, chainId, selectData>;
export type GetTransactionQueryFnData<config extends Config, chainId extends config['chains'][number]['id']> = GetTransactionReturnType<config, chainId>;
export type GetTransactionData<config extends Config, chainId extends config['chains'][number]['id']> = GetTransactionQueryFnData<config, chainId>;
export declare function getTransactionQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<GetTransactionParameters<config, chainId>> & ScopeKeyParameter>): readonly ["transaction", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    nonce?: number | undefined;
    blockHash?: `0x${string}` | undefined;
    blockNumber?: bigint | undefined;
    hash?: `0x${string}` | undefined;
    sender?: `0x${string}` | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    index?: number | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetTransactionQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getTransactionQueryKey<config, chainId>>;
export type GetTransactionQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetTransactionData<config, chainId>> = QueryOptions<GetTransactionQueryFnData<config, chainId>, GetTransactionErrorType, selectData, GetTransactionQueryKey<config, chainId>>;
//# sourceMappingURL=getTransaction.d.ts.map