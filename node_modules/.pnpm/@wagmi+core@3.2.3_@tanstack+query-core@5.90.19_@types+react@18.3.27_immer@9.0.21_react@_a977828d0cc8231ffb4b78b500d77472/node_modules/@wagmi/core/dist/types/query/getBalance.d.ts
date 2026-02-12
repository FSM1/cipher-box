import { type GetBalanceErrorType, type GetBalanceParameters, type GetBalanceReturnType } from '../actions/getBalance.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetBalanceOptions<config extends Config, selectData = GetBalanceData> = Compute<ExactPartial<GetBalanceParameters<config>> & ScopeKeyParameter> & QueryParameter<GetBalanceQueryFnData, GetBalanceErrorType, selectData, GetBalanceQueryKey<config>>;
export declare function getBalanceQueryOptions<config extends Config, selectData = GetBalanceData>(config: config, options?: GetBalanceOptions<config, selectData>): GetBalanceQueryOptions<config, selectData>;
export type GetBalanceQueryFnData = Compute<GetBalanceReturnType>;
export type GetBalanceData = GetBalanceQueryFnData;
export declare function getBalanceQueryKey<config extends Config>(options?: Compute<ExactPartial<GetBalanceParameters<config>> & ScopeKeyParameter>): readonly ["balance", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    address?: `0x${string}` | undefined;
    blockNumber?: bigint | undefined | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetBalanceQueryKey<config extends Config> = ReturnType<typeof getBalanceQueryKey<config>>;
export type GetBalanceQueryOptions<config extends Config, selectData = GetBalanceData> = QueryOptions<GetBalanceQueryFnData, GetBalanceErrorType, selectData, GetBalanceQueryKey<config>>;
//# sourceMappingURL=getBalance.d.ts.map