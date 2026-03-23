import type { Config, GetEnsResolverErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetEnsResolverData, type GetEnsResolverOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseEnsResolverParameters<config extends Config = Config, selectData = GetEnsResolverData> = Compute<GetEnsResolverOptions<config, selectData> & ConfigParameter<config>>;
export type UseEnsResolverReturnType<selectData = GetEnsResolverData> = UseQueryReturnType<selectData, GetEnsResolverErrorType>;
/** https://wagmi.sh/react/api/hooks/useEnsResolver */
export declare function useEnsResolver<config extends Config = ResolvedRegister['config'], selectData = GetEnsResolverData>(parameters?: UseEnsResolverParameters<config, selectData>): UseEnsResolverReturnType<selectData>;
//# sourceMappingURL=useEnsResolver.d.ts.map