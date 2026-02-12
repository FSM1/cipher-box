import type { Config, GetStorageAtErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetStorageAtData, type GetStorageAtOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseStorageAtParameters<config extends Config = Config, selectData = GetStorageAtData> = Compute<GetStorageAtOptions<config, selectData> & ConfigParameter<config>>;
export type UseStorageAtReturnType<selectData = GetStorageAtData> = UseQueryReturnType<selectData, GetStorageAtErrorType>;
/** https://wagmi.sh/react/api/hooks/useStorageAt */
export declare function useStorageAt<config extends Config = ResolvedRegister['config'], selectData = GetStorageAtData>(parameters?: UseStorageAtParameters<config, selectData>): UseStorageAtReturnType<selectData>;
//# sourceMappingURL=useStorageAt.d.ts.map