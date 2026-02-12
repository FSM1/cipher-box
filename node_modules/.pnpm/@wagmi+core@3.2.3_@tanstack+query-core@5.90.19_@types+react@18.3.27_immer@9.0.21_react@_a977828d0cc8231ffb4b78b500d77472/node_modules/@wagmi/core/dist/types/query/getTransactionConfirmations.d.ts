import { type GetTransactionConfirmationsErrorType, type GetTransactionConfirmationsParameters, type GetTransactionConfirmationsReturnType } from '../actions/getTransactionConfirmations.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { UnionExactPartial } from '../types/utils.js';
export type GetTransactionConfirmationsOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = config['chains'][number]['id'], selectData = GetTransactionConfirmationsData> = UnionExactPartial<GetTransactionConfirmationsParameters<config, chainId>> & ScopeKeyParameter & QueryParameter<GetTransactionConfirmationsQueryFnData, GetTransactionConfirmationsErrorType, selectData, GetTransactionConfirmationsQueryKey<config, chainId>>;
export declare function getTransactionConfirmationsQueryOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = config['chains'][number]['id'], selectData = GetTransactionConfirmationsData>(config: config, options?: GetTransactionConfirmationsOptions<config, chainId, selectData>): GetTransactionConfirmationsQueryOptions<config, chainId, selectData>;
export type GetTransactionConfirmationsQueryFnData = GetTransactionConfirmationsReturnType;
export type GetTransactionConfirmationsData = GetTransactionConfirmationsQueryFnData;
export declare function getTransactionConfirmationsQueryKey<config extends Config, chainId extends config['chains'][number]['id'] | undefined = config['chains'][number]['id']>(options?: UnionExactPartial<GetTransactionConfirmationsParameters<config, chainId>> & ScopeKeyParameter): readonly ["transactionConfirmations", {
    [x: string]: unknown;
    connectorUid?: string | undefined;
}];
export type GetTransactionConfirmationsQueryKey<config extends Config, chainId extends config['chains'][number]['id'] | undefined = config['chains'][number]['id']> = ReturnType<typeof getTransactionConfirmationsQueryKey<config, chainId>>;
export type GetTransactionConfirmationsQueryOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = config['chains'][number]['id'], selectData = GetTransactionConfirmationsData> = QueryOptions<GetTransactionConfirmationsQueryFnData, GetTransactionConfirmationsErrorType, selectData, GetTransactionConfirmationsQueryKey<config, chainId>>;
//# sourceMappingURL=getTransactionConfirmations.d.ts.map