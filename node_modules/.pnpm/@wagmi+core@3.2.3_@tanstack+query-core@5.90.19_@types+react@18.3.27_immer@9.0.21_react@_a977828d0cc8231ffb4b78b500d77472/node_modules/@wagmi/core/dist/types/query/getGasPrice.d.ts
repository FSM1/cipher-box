import { type GetGasPriceErrorType, type GetGasPriceParameters, type GetGasPriceReturnType } from '../actions/getGasPrice.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type GetGasPriceOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetGasPriceData> = Compute<ExactPartial<GetGasPriceParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<GetGasPriceQueryFnData, GetGasPriceErrorType, selectData, GetGasPriceQueryKey<config, chainId>>;
export declare function getGasPriceQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetGasPriceData>(config: config, options?: GetGasPriceOptions<config, chainId, selectData>): GetGasPriceQueryOptions<config, chainId, selectData>;
export type GetGasPriceQueryFnData = GetGasPriceReturnType;
export type GetGasPriceData = GetGasPriceQueryFnData;
export declare function getGasPriceQueryKey<config extends Config, chainId extends config['chains'][number]['id']>(options?: Compute<ExactPartial<GetGasPriceParameters<config, chainId>> & ScopeKeyParameter>): readonly ["gasPrice", {
    chainId?: config["chains"][number]["id"] | (chainId extends config["chains"][number]["id"] ? chainId : undefined) | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type GetGasPriceQueryKey<config extends Config, chainId extends config['chains'][number]['id']> = ReturnType<typeof getGasPriceQueryKey<config, chainId>>;
export type GetGasPriceQueryOptions<config extends Config, chainId extends config['chains'][number]['id'], selectData = GetGasPriceData> = QueryOptions<GetGasPriceQueryFnData, GetGasPriceErrorType, selectData, GetGasPriceQueryKey<config, chainId>>;
//# sourceMappingURL=getGasPrice.d.ts.map