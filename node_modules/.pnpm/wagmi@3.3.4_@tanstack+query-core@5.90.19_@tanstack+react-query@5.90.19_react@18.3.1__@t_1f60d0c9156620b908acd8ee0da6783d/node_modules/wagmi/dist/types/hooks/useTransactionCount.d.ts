import type { Config, GetTransactionCountErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetTransactionCountData, type GetTransactionCountOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseTransactionCountParameters<config extends Config = Config, selectData = GetTransactionCountData> = Compute<GetTransactionCountOptions<config, selectData> & ConfigParameter<config>>;
export type UseTransactionCountReturnType<selectData = GetTransactionCountData> = UseQueryReturnType<selectData, GetTransactionCountErrorType>;
/** https://wagmi.sh/react/api/hooks/useTransactionCount */
export declare function useTransactionCount<config extends Config = ResolvedRegister['config'], selectData = GetTransactionCountData>(parameters?: UseTransactionCountParameters<config, selectData>): UseTransactionCountReturnType<selectData>;
//# sourceMappingURL=useTransactionCount.d.ts.map