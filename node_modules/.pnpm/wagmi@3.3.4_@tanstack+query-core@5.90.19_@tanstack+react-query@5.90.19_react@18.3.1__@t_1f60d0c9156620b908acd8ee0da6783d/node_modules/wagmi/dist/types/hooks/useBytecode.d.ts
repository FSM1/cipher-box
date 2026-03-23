import type { Config, GetBytecodeErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetBytecodeData, type GetBytecodeOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseBytecodeParameters<config extends Config = Config, selectData = GetBytecodeData> = Compute<GetBytecodeOptions<config, selectData> & ConfigParameter<config>>;
export type UseBytecodeReturnType<selectData = GetBytecodeData> = UseQueryReturnType<selectData, GetBytecodeErrorType>;
/** https://wagmi.sh/react/api/hooks/useBytecode */
export declare function useBytecode<config extends Config = ResolvedRegister['config'], selectData = GetBytecodeData>(parameters?: UseBytecodeParameters<config, selectData>): UseBytecodeReturnType<selectData>;
//# sourceMappingURL=useBytecode.d.ts.map