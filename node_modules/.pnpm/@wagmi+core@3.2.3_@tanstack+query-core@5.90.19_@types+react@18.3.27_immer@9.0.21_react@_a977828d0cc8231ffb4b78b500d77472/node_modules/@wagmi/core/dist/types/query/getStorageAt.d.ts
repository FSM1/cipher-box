import { type GetStorageAtErrorType, type GetStorageAtParameters, type GetStorageAtReturnType } from '../actions/getStorageAt.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetStorageAtOptions<config extends Config, selectData = GetStorageAtData> = Compute<ExactPartial<GetStorageAtParameters<config>> & ScopeKeyParameter> & QueryParameter<GetStorageAtQueryFnData, GetStorageAtErrorType, selectData, GetStorageAtQueryKey<config>>;
export declare function getStorageAtQueryOptions<config extends Config, selectData = GetStorageAtData>(config: config, options?: GetStorageAtOptions<config, selectData>): GetStorageAtQueryOptions<config, selectData>;
export type GetStorageAtQueryFnData = GetStorageAtReturnType;
export type GetStorageAtData = GetStorageAtQueryFnData;
export declare function getStorageAtQueryKey<config extends Config>(options?: Compute<ExactPartial<GetStorageAtParameters<config>> & ScopeKeyParameter>): readonly ["getStorageAt", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    address?: `0x${string}` | undefined;
    blockNumber?: bigint | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    slot?: `0x${string}` | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetStorageAtQueryKey<config extends Config> = ReturnType<typeof getStorageAtQueryKey<config>>;
export type GetStorageAtQueryOptions<config extends Config, selectData = GetStorageAtData> = QueryOptions<GetStorageAtQueryFnData, GetStorageAtErrorType, selectData, GetStorageAtQueryKey<config>>;
//# sourceMappingURL=getStorageAt.d.ts.map