import { type GetCapabilitiesErrorType, type GetCapabilitiesParameters, type GetCapabilitiesReturnType } from '../actions/getCapabilities.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetCapabilitiesOptions<config extends Config = Config, chainId extends config['chains'][number]['id'] | undefined = undefined, selectData = GetCapabilitiesData<config, chainId>> = Compute<ExactPartial<GetCapabilitiesParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetCapabilitiesQueryFnData<config, chainId>, GetCapabilitiesErrorType, selectData, GetCapabilitiesQueryKey<config, chainId>>;
export declare function getCapabilitiesQueryOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined, selectData = GetCapabilitiesData<config, chainId>>(config: config, options?: GetCapabilitiesOptions<config, chainId, selectData>): GetCapabilitiesQueryOptions<config, chainId, selectData>;
export type GetCapabilitiesQueryFnData<config extends Config = Config, chainId extends config['chains'][number]['id'] | undefined = undefined> = GetCapabilitiesReturnType<config, chainId>;
export type GetCapabilitiesData<config extends Config = Config, chainId extends config['chains'][number]['id'] | undefined = undefined> = GetCapabilitiesQueryFnData<config, chainId>;
export declare function getCapabilitiesQueryKey<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined>(options?: Compute<ExactPartial<GetCapabilitiesParameters<config, chainId>> & ScopeKeyParameter>): readonly ["capabilities", {
    chainId?: number | chainId | undefined;
    account?: `0x${string}` | import("viem").Account | undefined;
    scopeKey?: string | undefined | undefined;
    connectorUid?: string | undefined;
}];
export type GetCapabilitiesQueryKey<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined> = ReturnType<typeof getCapabilitiesQueryKey<config, chainId>>;
export type GetCapabilitiesQueryOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined, selectData = GetCapabilitiesData<config, chainId>> = QueryOptions<GetCapabilitiesQueryFnData<config, chainId>, GetCapabilitiesErrorType, selectData, GetCapabilitiesQueryKey<config, chainId>>;
//# sourceMappingURL=getCapabilities.d.ts.map