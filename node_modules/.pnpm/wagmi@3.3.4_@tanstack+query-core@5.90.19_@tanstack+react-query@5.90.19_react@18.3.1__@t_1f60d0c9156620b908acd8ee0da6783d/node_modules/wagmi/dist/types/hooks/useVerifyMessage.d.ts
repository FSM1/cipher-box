import type { Config, ResolvedRegister, VerifyMessageErrorType } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type VerifyMessageData, type VerifyMessageOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseVerifyMessageParameters<config extends Config = Config, selectData = VerifyMessageData> = Compute<VerifyMessageOptions<config, selectData> & ConfigParameter<config>>;
export type UseVerifyMessageReturnType<selectData = VerifyMessageData> = UseQueryReturnType<selectData, VerifyMessageErrorType>;
/** https://wagmi.sh/react/api/hooks/useVerifyMessage */
export declare function useVerifyMessage<config extends Config = ResolvedRegister['config'], selectData = VerifyMessageData>(parameters?: UseVerifyMessageParameters<config, selectData>): UseVerifyMessageReturnType<selectData>;
//# sourceMappingURL=useVerifyMessage.d.ts.map