import { type GetProofErrorType, type GetProofParameters, type GetProofReturnType } from '../actions/getProof.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetProofOptions<config extends Config, selectData = GetProofData> = Compute<ExactPartial<GetProofParameters<config>> & ScopeKeyParameter> & QueryParameter<GetProofQueryFnData, GetProofErrorType, selectData, GetProofQueryKey<config>>;
export declare function getProofQueryOptions<config extends Config, selectData = GetProofData>(config: config, options?: GetProofOptions<config, selectData>): GetProofQueryOptions<config, selectData>;
export type GetProofQueryFnData = GetProofReturnType;
export type GetProofData = GetProofQueryFnData;
export declare function getProofQueryKey<config extends Config>(options?: Compute<ExactPartial<GetProofParameters<config>> & ScopeKeyParameter>): readonly ["getProof", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    address?: `0x${string}` | undefined;
    blockNumber?: bigint | undefined | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    storageKeys?: `0x${string}`[] | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetProofQueryKey<config extends Config> = ReturnType<typeof getProofQueryKey<config>>;
export type GetProofQueryOptions<config extends Config, selectData = GetProofData> = QueryOptions<GetProofQueryFnData, GetProofErrorType, selectData, GetProofQueryKey<config>>;
//# sourceMappingURL=getProof.d.ts.map