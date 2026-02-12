import type { TypedData } from 'viem';
import { type VerifyTypedDataErrorType, type VerifyTypedDataParameters, type VerifyTypedDataReturnType } from '../actions/verifyTypedData.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { UnionExactPartial } from '../types/utils.js';
export type VerifyTypedDataOptions<typedData extends TypedData | Record<string, unknown>, primaryType extends keyof typedData | 'EIP712Domain', config extends Config, selectData = VerifyTypedDataData> = UnionExactPartial<VerifyTypedDataParameters<typedData, primaryType, config>> & ScopeKeyParameter & QueryParameter<VerifyTypedDataQueryFnData, VerifyTypedDataErrorType, selectData, VerifyTypedDataQueryKey<typedData, primaryType, config>>;
export declare function verifyTypedDataQueryOptions<const typedData extends TypedData | Record<string, unknown>, primaryType extends keyof typedData | 'EIP712Domain', config extends Config, selectData = VerifyTypedDataData>(config: config, options?: VerifyTypedDataOptions<typedData, primaryType, config, selectData>): VerifyTypedDataQueryOptions<typedData, primaryType, config, selectData>;
export type VerifyTypedDataQueryFnData = VerifyTypedDataReturnType;
export type VerifyTypedDataData = VerifyTypedDataQueryFnData;
export declare function verifyTypedDataQueryKey<config extends Config, const typedData extends TypedData | Record<string, unknown>, primaryType extends keyof typedData | 'EIP712Domain'>(options?: UnionExactPartial<VerifyTypedDataParameters<typedData, primaryType, config>> & ScopeKeyParameter): readonly ["verifyTypedData", {
    [x: string]: unknown;
    connectorUid?: string | undefined;
}];
export type VerifyTypedDataQueryKey<typedData extends TypedData | Record<string, unknown>, primaryType extends keyof typedData | 'EIP712Domain', config extends Config> = ReturnType<typeof verifyTypedDataQueryKey<config, typedData, primaryType>>;
export type VerifyTypedDataQueryOptions<typedData extends TypedData | Record<string, unknown>, primaryType extends keyof typedData | 'EIP712Domain', config extends Config, selectData = VerifyTypedDataData> = QueryOptions<VerifyTypedDataQueryFnData, VerifyTypedDataErrorType, selectData, VerifyTypedDataQueryKey<typedData, primaryType, config>>;
//# sourceMappingURL=verifyTypedData.d.ts.map