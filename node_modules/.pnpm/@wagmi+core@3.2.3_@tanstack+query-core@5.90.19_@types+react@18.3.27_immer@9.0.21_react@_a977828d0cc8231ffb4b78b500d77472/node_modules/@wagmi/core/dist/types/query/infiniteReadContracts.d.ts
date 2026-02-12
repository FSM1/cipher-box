import type { ContractFunctionParameters } from 'viem';
import { type ReadContractsParameters, type ReadContractsReturnType } from '../actions/readContracts.js';
import type { Config } from '../createConfig.js';
import type { ChainIdParameter, ScopeKeyParameter } from '../types/properties.js';
import type { StrictOmit } from '../types/utils.js';
export type InfiniteReadContractsOptions<contracts extends readonly unknown[], allowFailure extends boolean, pageParam, config extends Config> = {
    cacheKey: string;
    contracts(pageParam: pageParam): ReadContractsParameters<contracts, allowFailure, config>['contracts'];
} & StrictOmit<ReadContractsParameters<contracts, allowFailure, config>, 'contracts'> & ScopeKeyParameter;
export declare function infiniteReadContractsQueryOptions<config extends Config, const contracts extends readonly ContractFunctionParameters[], allowFailure extends boolean = true, pageParam = unknown>(config: config, options: InfiniteReadContractsOptions<contracts, allowFailure, pageParam, config> & ChainIdParameter<config> & RequiredPageParamsParameters<contracts, allowFailure, pageParam>): {
    readonly queryFn: ({ pageParam, queryKey }: import("@tanstack/query-core").QueryFunctionContext<readonly ["infiniteReadContracts", {
        chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
        account?: `0x${string}` | undefined;
        authorizationList?: import("viem").AuthorizationList<number, boolean> | undefined;
        blockNumber?: bigint | undefined | undefined;
        batchSize?: number | undefined | undefined;
        deployless?: boolean | undefined | undefined;
        blockOverrides?: import("viem").BlockOverrides<bigint, number> | undefined;
        stateOverride?: import("viem").StateOverride | undefined;
        blockTag?: import("viem").BlockTag | undefined;
        multicallAddress?: `0x${string}` | undefined;
        allowFailure?: boolean | allowFailure | undefined;
        scopeKey?: string | undefined | undefined;
        cacheKey: string;
    }], pageParam>) => Promise<ReadContractsReturnType<contracts, allowFailure>>;
    readonly queryKey: readonly ["infiniteReadContracts", {
        chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
        account?: `0x${string}` | undefined;
        authorizationList?: import("viem").AuthorizationList<number, boolean> | undefined;
        blockNumber?: bigint | undefined | undefined;
        batchSize?: number | undefined | undefined;
        deployless?: boolean | undefined | undefined;
        blockOverrides?: import("viem").BlockOverrides<bigint, number> | undefined;
        stateOverride?: import("viem").StateOverride | undefined;
        blockTag?: import("viem").BlockTag | undefined;
        multicallAddress?: `0x${string}` | undefined;
        allowFailure?: boolean | allowFailure | undefined;
        scopeKey?: string | undefined | undefined;
        cacheKey: string;
    }];
    readonly initialPageParam: pageParam;
    readonly getNextPageParam: (lastPage: InfiniteReadContractsQueryFnData<contracts, allowFailure>, allPages: InfiniteReadContractsQueryFnData<contracts, allowFailure>[], lastPageParam: pageParam, allPageParams: pageParam[]) => pageParam | null | undefined;
};
type RequiredPageParamsParameters<contracts extends readonly unknown[], allowFailure extends boolean, pageParam> = {
    query: {
        initialPageParam: pageParam;
        getNextPageParam(lastPage: InfiniteReadContractsQueryFnData<contracts, allowFailure>, allPages: InfiniteReadContractsQueryFnData<contracts, allowFailure>[], lastPageParam: pageParam, allPageParams: pageParam[]): pageParam | undefined | null;
    };
};
export type InfiniteReadContractsQueryFnData<contracts extends readonly unknown[], allowFailure extends boolean> = ReadContractsReturnType<contracts, allowFailure>;
export type InfiniteReadContractsData<contracts extends readonly unknown[], allowFailure extends boolean> = InfiniteReadContractsQueryFnData<contracts, allowFailure>;
export declare function infiniteReadContractsQueryKey<config extends Config, const contracts extends readonly unknown[], allowFailure extends boolean, pageParam>(options: InfiniteReadContractsOptions<contracts, allowFailure, pageParam, config> & ChainIdParameter<config> & RequiredPageParamsParameters<contracts, allowFailure, pageParam>): readonly ["infiniteReadContracts", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    account?: `0x${string}` | undefined;
    authorizationList?: import("viem").AuthorizationList<number, boolean> | undefined;
    blockNumber?: bigint | undefined | undefined;
    batchSize?: number | undefined | undefined;
    deployless?: boolean | undefined | undefined;
    blockOverrides?: import("viem").BlockOverrides<bigint, number> | undefined;
    stateOverride?: import("viem").StateOverride | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    multicallAddress?: `0x${string}` | undefined;
    allowFailure?: boolean | allowFailure | undefined;
    scopeKey?: string | undefined | undefined;
    cacheKey: string;
}];
export type InfiniteReadContractsQueryKey<contracts extends readonly unknown[], allowFailure extends boolean, pageParam, config extends Config> = ReturnType<typeof infiniteReadContractsQueryKey<config, contracts, allowFailure, pageParam>>;
export {};
//# sourceMappingURL=infiniteReadContracts.d.ts.map