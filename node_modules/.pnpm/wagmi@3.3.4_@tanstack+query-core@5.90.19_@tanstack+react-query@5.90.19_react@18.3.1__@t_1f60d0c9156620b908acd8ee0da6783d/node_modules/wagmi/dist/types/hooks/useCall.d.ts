import type { CallErrorType, Config, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type CallData, type CallOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseCallParameters<config extends Config = Config, selectData = CallData> = Compute<CallOptions<config, selectData> & ConfigParameter<config>>;
export type UseCallReturnType<selectData = CallData> = UseQueryReturnType<selectData, CallErrorType>;
/** https://wagmi.sh/react/api/hooks/useCall */
export declare function useCall<config extends Config = ResolvedRegister['config'], selectData = CallData>(parameters?: UseCallParameters<config, selectData>): UseCallReturnType<selectData>;
//# sourceMappingURL=useCall.d.ts.map