import { type WaitForTransactionReceiptErrorType, type WaitForTransactionReceiptParameters, type WaitForTransactionReceiptReturnType } from '../actions/waitForTransactionReceipt.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type WaitForTransactionReceiptOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = WaitForTransactionReceiptData<config, chainId>> = Compute<ExactPartial<WaitForTransactionReceiptParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<WaitForTransactionReceiptQueryFnData<config, chainId>, WaitForTransactionReceiptErrorType, selectData, WaitForTransactionReceiptQueryKey<config, chainId>>;
export declare function waitForTransactionReceiptQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = WaitForTransactionReceiptData<config, chainId>>(config: config, options?: WaitForTransactionReceiptOptions<config, chainId, selectData>): WaitForTransactionReceiptQueryOptions<config, chainId, selectData>;
export type WaitForTransactionReceiptQueryFnData<config extends Config, chainId extends config['chains'][number]['id']> = WaitForTransactionReceiptReturnType<config, chainId>;
export type WaitForTransactionReceiptData<config extends Config, chainId extends config['chains'][number]['id']> = WaitForTransactionReceiptQueryFnData<config, chainId>;
export declare function waitForTransactionReceiptQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<WaitForTransactionReceiptParameters<config, chainId>> & ScopeKeyParameter>): readonly ["waitForTransactionReceipt", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    pollingInterval?: number | undefined | undefined;
    hash?: `0x${string}` | undefined;
    retryCount?: number | undefined;
    timeout?: number | undefined | undefined;
    retryDelay?: number | ((config: {
        count: number;
        error: Error;
    }) => number) | undefined;
    checkReplacement?: boolean | undefined | undefined;
    confirmations?: number | undefined | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type WaitForTransactionReceiptQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof waitForTransactionReceiptQueryKey<config, chainId>>;
export type WaitForTransactionReceiptQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = WaitForTransactionReceiptData<config, chainId>> = QueryOptions<WaitForTransactionReceiptQueryFnData<config, chainId>, WaitForTransactionReceiptErrorType, selectData, WaitForTransactionReceiptQueryKey<config, chainId>>;
//# sourceMappingURL=waitForTransactionReceipt.d.ts.map