import type { Config, GetEnsAvatarErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetEnsAvatarData, type GetEnsAvatarOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseEnsAvatarParameters<config extends Config = Config, selectData = GetEnsAvatarData> = Compute<GetEnsAvatarOptions<config, selectData> & ConfigParameter<config>>;
export type UseEnsAvatarReturnType<selectData = GetEnsAvatarData> = UseQueryReturnType<selectData, GetEnsAvatarErrorType>;
/** https://wagmi.sh/react/api/hooks/useEnsAvatar */
export declare function useEnsAvatar<config extends Config = ResolvedRegister['config'], selectData = GetEnsAvatarData>(parameters?: UseEnsAvatarParameters<config, selectData>): UseEnsAvatarReturnType<selectData>;
//# sourceMappingURL=useEnsAvatar.d.ts.map