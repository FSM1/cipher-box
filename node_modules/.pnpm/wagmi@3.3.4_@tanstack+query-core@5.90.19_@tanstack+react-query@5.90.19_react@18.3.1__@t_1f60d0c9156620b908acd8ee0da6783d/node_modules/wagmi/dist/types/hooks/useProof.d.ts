import type { Config, GetProofErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetProofData, type GetProofOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseProofParameters<config extends Config = Config, selectData = GetProofData> = Compute<GetProofOptions<config, selectData> & ConfigParameter<config>>;
export type UseProofReturnType<selectData = GetProofData> = UseQueryReturnType<selectData, GetProofErrorType>;
/** https://wagmi.sh/react/api/hooks/useProof */
export declare function useProof<config extends Config = ResolvedRegister['config'], selectData = GetProofData>(parameters?: UseProofParameters<config, selectData>): UseProofReturnType<selectData>;
//# sourceMappingURL=useProof.d.ts.map