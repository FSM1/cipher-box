import type { Config, GetEnsNameErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetEnsNameData, type GetEnsNameOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseEnsNameParameters<config extends Config = Config, selectData = GetEnsNameData> = Compute<GetEnsNameOptions<config, selectData> & ConfigParameter<config>>;
export type UseEnsNameReturnType<selectData = GetEnsNameData> = UseQueryReturnType<selectData, GetEnsNameErrorType>;
/** https://wagmi.sh/react/api/hooks/useEnsName */
export declare function useEnsName<config extends Config = ResolvedRegister['config'], selectData = GetEnsNameData>(parameters?: UseEnsNameParameters<config, selectData>): UseEnsNameReturnType<selectData>;
//# sourceMappingURL=useEnsName.d.ts.map