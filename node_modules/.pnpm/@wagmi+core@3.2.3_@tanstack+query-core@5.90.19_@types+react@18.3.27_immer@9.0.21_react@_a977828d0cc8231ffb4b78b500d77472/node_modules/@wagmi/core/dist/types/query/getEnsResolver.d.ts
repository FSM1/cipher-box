import { type GetEnsResolverErrorType, type GetEnsResolverParameters, type GetEnsResolverReturnType } from '../actions/getEnsResolver.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetEnsResolverOptions<config extends Config, selectData = GetEnsResolverData> = Compute<ExactPartial<GetEnsResolverParameters<config>> & ScopeKeyParameter> & QueryParameter<GetEnsResolverQueryFnData, GetEnsResolverErrorType, selectData, GetEnsResolverQueryKey<config>>;
export declare function getEnsResolverQueryOptions<config extends Config, selectData = GetEnsResolverData>(config: config, options?: GetEnsResolverOptions<config, selectData>): GetEnsResolverQueryOptions<config, selectData>;
export type GetEnsResolverQueryFnData = GetEnsResolverReturnType;
export type GetEnsResolverData = GetEnsResolverQueryFnData;
export declare function getEnsResolverQueryKey<config extends Config>(options?: Compute<ExactPartial<GetEnsResolverParameters<config>> & ScopeKeyParameter>): readonly ["ensResolver", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    name?: string | undefined;
    blockNumber?: bigint | undefined | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    universalResolverAddress?: `0x${string}` | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetEnsResolverQueryKey<config extends Config> = ReturnType<typeof getEnsResolverQueryKey<config>>;
export type GetEnsResolverQueryOptions<config extends Config, selectData = GetEnsResolverData> = QueryOptions<GetEnsResolverQueryFnData, GetEnsResolverErrorType, selectData, GetEnsResolverQueryKey<config>>;
//# sourceMappingURL=getEnsResolver.d.ts.map