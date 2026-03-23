import { type GetWalletClientErrorType, type GetWalletClientParameters, type GetWalletClientReturnType } from '../actions/getWalletClient.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetWalletClientOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetWalletClientData<config, chainId>> = Compute<ExactPartial<GetWalletClientParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetWalletClientQueryFnData<config, chainId>, GetWalletClientErrorType, selectData, GetWalletClientQueryKey<config, chainId>>;
export declare function getWalletClientQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetWalletClientData<config, chainId>>(config: config, options?: GetWalletClientOptions<config, chainId, selectData>): GetWalletClientQueryOptions<config, chainId, selectData>;
export type GetWalletClientQueryFnData<config extends Config, chainId extends config['chains'][number]['id']> = GetWalletClientReturnType<config, chainId>;
export type GetWalletClientData<config extends Config, chainId extends config['chains'][number]['id']> = GetWalletClientQueryFnData<config, chainId>;
export declare function getWalletClientQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<GetWalletClientParameters<config, chainId>> & ScopeKeyParameter>): readonly ["walletClient", {
    chainId?: number | (chainId extends number ? chainId : undefined) | undefined;
    account?: `0x${string}` | import("viem").Account | null | undefined;
    assertChainId?: boolean | undefined | undefined;
    scopeKey?: string | undefined | undefined;
    connectorUid?: string | undefined;
}];
export type GetWalletClientQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getWalletClientQueryKey<config, chainId>>;
export type GetWalletClientQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetWalletClientData<config, chainId>> = QueryOptions<GetWalletClientQueryFnData<config, chainId>, GetWalletClientErrorType, selectData, GetWalletClientQueryKey<config, chainId>>;
//# sourceMappingURL=getWalletClient.d.ts.map