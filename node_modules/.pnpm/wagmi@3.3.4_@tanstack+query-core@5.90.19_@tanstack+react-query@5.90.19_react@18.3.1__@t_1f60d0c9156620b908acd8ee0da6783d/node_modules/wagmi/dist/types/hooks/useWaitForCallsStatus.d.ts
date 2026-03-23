import type { Config, ResolvedRegister, WaitForCallsStatusErrorType } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type WaitForCallsStatusData, type WaitForCallsStatusOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseWaitForCallsStatusParameters<config extends Config = Config, selectData = WaitForCallsStatusData> = Compute<WaitForCallsStatusOptions<selectData> & ConfigParameter<config>>;
export type UseWaitForCallsStatusReturnType<selectData = WaitForCallsStatusData> = UseQueryReturnType<selectData, WaitForCallsStatusErrorType>;
/** https://wagmi.sh/react/api/hooks/useWaitForCallsStatus */
export declare function useWaitForCallsStatus<config extends Config = ResolvedRegister['config'], selectData = WaitForCallsStatusData>(parameters: UseWaitForCallsStatusParameters<config, selectData>): UseWaitForCallsStatusReturnType<selectData>;
//# sourceMappingURL=useWaitForCallsStatus.d.ts.map