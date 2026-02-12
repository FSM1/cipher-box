import type { Config, GetFeeHistoryErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetFeeHistoryData, type GetFeeHistoryOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseFeeHistoryParameters<config extends Config = Config, chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetFeeHistoryData> = Compute<GetFeeHistoryOptions<config, chainId, selectData> & ConfigParameter<config>>;
export type UseFeeHistoryReturnType<selectData = GetFeeHistoryData> = UseQueryReturnType<selectData, GetFeeHistoryErrorType>;
/** https://wagmi.sh/react/api/hooks/useFeeHistory */
export declare function useFeeHistory<config extends Config = ResolvedRegister['config'], chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetFeeHistoryData>(parameters?: UseFeeHistoryParameters<config, chainId, selectData>): UseFeeHistoryReturnType<selectData>;
//# sourceMappingURL=useFeeHistory.d.ts.map