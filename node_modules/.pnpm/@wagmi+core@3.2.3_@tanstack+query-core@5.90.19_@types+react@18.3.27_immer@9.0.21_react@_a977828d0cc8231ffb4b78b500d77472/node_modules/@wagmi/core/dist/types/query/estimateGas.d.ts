import { type EstimateGasErrorType, type EstimateGasParameters, type EstimateGasReturnType } from '../actions/estimateGas.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, UnionExactPartial } from '../types/utils.js';
export type EstimateGasOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined, selectData = EstimateGasData> = Compute<UnionExactPartial<EstimateGasParameters<config, chainId>> & ScopeKeyParameter> & QueryParameter<EstimateGasQueryFnData, EstimateGasErrorType, selectData, EstimateGasQueryKey<config, chainId>>;
export declare function estimateGasQueryOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined, selectData = EstimateGasData>(config: config, options?: EstimateGasOptions<config, chainId, selectData>): EstimateGasQueryOptions<config, chainId, selectData>;
export type EstimateGasQueryFnData = EstimateGasReturnType;
export type EstimateGasData = EstimateGasQueryFnData;
export declare function estimateGasQueryKey<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined>(options?: Compute<UnionExactPartial<EstimateGasParameters<config, chainId>> & ScopeKeyParameter>): readonly ["estimateGas", import("../types/utils.js").StrictOmit<UnionExactPartial<EstimateGasParameters<config, chainId>> & ScopeKeyParameter extends infer T_1 ? { [key_1 in keyof T_1]: T_1[key_1]; } : never, "connector" | "config" | "abi" | "query" | "watch"> & ((UnionExactPartial<EstimateGasParameters<config, chainId>> & ScopeKeyParameter extends infer T_2 ? { [key_1 in keyof T_2]: T_2[key_1]; } : never) extends infer T_3 ? T_3 extends (UnionExactPartial<EstimateGasParameters<config, chainId>> & ScopeKeyParameter extends infer T_4 ? { [key_1 in keyof T_4]: T_4[key_1]; } : never) ? T_3 extends {
    connector?: import("../createConfig.js").Connector | undefined;
} ? {
    connectorUid?: string;
} : unknown : never : never) extends infer T ? { [key in keyof T]: T[key]; } : never];
export type EstimateGasQueryKey<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined> = ReturnType<typeof estimateGasQueryKey<config, chainId>>;
export type EstimateGasQueryOptions<config extends Config, chainId extends config['chains'][number]['id'] | undefined = undefined, selectData = EstimateGasData> = QueryOptions<EstimateGasQueryFnData, EstimateGasErrorType, selectData, EstimateGasQueryKey<config, chainId>>;
//# sourceMappingURL=estimateGas.d.ts.map