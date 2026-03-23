import type { GetTransactionReceiptReturnType } from '../actions/getTransactionReceipt.js';
import { type GetTransactionReceiptErrorType, type GetTransactionReceiptParameters } from '../actions/getTransactionReceipt.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetTransactionReceiptOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetTransactionReceiptData<config, chainId>> = Compute<ExactPartial<GetTransactionReceiptParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetTransactionReceiptQueryFnData<config, chainId>, GetTransactionReceiptErrorType, selectData, GetTransactionReceiptQueryKey<config, chainId>>;
export declare function getTransactionReceiptQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetTransactionReceiptData<config, chainId>>(config: config, options?: GetTransactionReceiptOptions<config, chainId, selectData>): GetTransactionReceiptQueryOptions<config, chainId, selectData>;
export type GetTransactionReceiptQueryFnData<config extends Config, chainId extends config['chains'][number]['id']> = GetTransactionReceiptReturnType<config, chainId>;
export type GetTransactionReceiptData<config extends Config, chainId extends config['chains'][number]['id']> = GetTransactionReceiptQueryFnData<config, chainId>;
export declare function getTransactionReceiptQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<GetTransactionReceiptParameters<config, chainId>> & ScopeKeyParameter>): readonly ["getTransactionReceipt", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    hash?: `0x${string}` | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetTransactionReceiptQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getTransactionReceiptQueryKey<config, chainId>>;
export type GetTransactionReceiptQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetTransactionReceiptData<config, chainId>> = QueryOptions<GetTransactionReceiptQueryFnData<config, chainId>, GetTransactionReceiptErrorType, selectData, GetTransactionReceiptQueryKey<config, chainId>>;
//# sourceMappingURL=getTransactionReceipt.d.ts.map