import type { Config, EstimateMaxPriorityFeePerGasErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type EstimateMaxPriorityFeePerGasData, type EstimateMaxPriorityFeePerGasOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseEstimateMaxPriorityFeePerGasParameters<config extends Config = Config, selectData = EstimateMaxPriorityFeePerGasData> = Compute<EstimateMaxPriorityFeePerGasOptions<config, selectData> & ConfigParameter<config>>;
export type UseEstimateMaxPriorityFeePerGasReturnType<selectData = EstimateMaxPriorityFeePerGasData> = UseQueryReturnType<selectData, EstimateMaxPriorityFeePerGasErrorType>;
/** https://wagmi.sh/react/api/hooks/useEstimateMaxPriorityFeePerGas */
export declare function useEstimateMaxPriorityFeePerGas<config extends Config = ResolvedRegister['config'], selectData = EstimateMaxPriorityFeePerGasData>(parameters?: UseEstimateMaxPriorityFeePerGasParameters<config, selectData>): UseEstimateMaxPriorityFeePerGasReturnType<selectData>;
//# sourceMappingURL=useEstimateMaxPriorityFeePerGas.d.ts.map