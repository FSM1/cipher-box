import { type GetBytecodeErrorType, type GetBytecodeParameters, type GetBytecodeReturnType } from '../actions/getBytecode.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetBytecodeOptions<config extends Config, selectData = GetBytecodeData> = Compute<ExactPartial<GetBytecodeParameters<config>> & ScopeKeyParameter> & QueryParameter<GetBytecodeQueryFnData, GetBytecodeErrorType, selectData, GetBytecodeQueryKey<config>>;
export declare function getBytecodeQueryOptions<config extends Config, selectData = GetBytecodeData>(config: config, options?: GetBytecodeOptions<config, selectData>): GetBytecodeQueryOptions<config, selectData>;
export type GetBytecodeQueryFnData = GetBytecodeReturnType;
export type GetBytecodeData = GetBytecodeQueryFnData;
export declare function getBytecodeQueryKey<config extends Config>(options?: Compute<ExactPartial<GetBytecodeParameters<config>> & ScopeKeyParameter>): readonly ["getBytecode", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    address?: `0x${string}` | undefined;
    blockNumber?: bigint | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetBytecodeQueryKey<config extends Config> = ReturnType<typeof getBytecodeQueryKey<config>>;
export type GetBytecodeQueryOptions<config extends Config, selectData = GetBytecodeData> = QueryOptions<GetBytecodeQueryFnData, GetBytecodeErrorType, selectData, GetBytecodeQueryKey<config>>;
//# sourceMappingURL=getBytecode.d.ts.map