import { type GetConnectorClientErrorType, type GetConnectorClientParameters, type GetConnectorClientReturnType } from '../actions/getConnectorClient.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetConnectorClientOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetConnectorClientData<config, chainId>> = Compute<ExactPartial<GetConnectorClientParameters<config, chainId>> & ScopeKeyParameter> & Omit<QueryParameter<GetConnectorClientQueryFnData<config, chainId>, GetConnectorClientErrorType, selectData, GetConnectorClientQueryKey<config, chainId>>, 'gcTime' | 'staleTime'>;
export declare function getConnectorClientQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetConnectorClientData<config, chainId>>(config: config, options?: GetConnectorClientOptions<config, chainId, selectData>): GetConnectorClientQueryOptions<config, chainId, selectData>;
export type GetConnectorClientQueryFnData<config extends Config, chainId extends config['chains'][number]['id']> = GetConnectorClientReturnType<config, chainId>;
export type GetConnectorClientData<config extends Config, chainId extends config['chains'][number]['id']> = GetConnectorClientQueryFnData<config, chainId>;
export declare function getConnectorClientQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<GetConnectorClientParameters<config, chainId>> & ScopeKeyParameter>): readonly ["connectorClient", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    account?: `0x${string}` | import("viem").Account | null | undefined;
    assertChainId?: boolean | undefined | undefined;
    scopeKey?: string | undefined | undefined;
    connectorUid?: string | undefined;
}];
export type GetConnectorClientQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getConnectorClientQueryKey<config, chainId>>;
export type GetConnectorClientQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetConnectorClientData<config, chainId>> = QueryOptions<GetConnectorClientQueryFnData<config, chainId>, GetConnectorClientErrorType, selectData, GetConnectorClientQueryKey<config, chainId>>;
//# sourceMappingURL=getConnectorClient.d.ts.map