import { type Config, type GetConnectionReturnType, type ResolvedRegister } from '@wagmi/core';
import type { ConfigParameter } from '../types/properties.js';
export type UseConnectionParameters<config extends Config = Config> = ConfigParameter<config>;
export type UseConnectionReturnType<config extends Config = Config> = GetConnectionReturnType<config>;
/** https://wagmi.sh/react/api/hooks/useConnection */
export declare function useConnection<config extends Config = ResolvedRegister['config']>(parameters?: UseConnectionParameters<config>): UseConnectionReturnType<config>;
//# sourceMappingURL=useConnection.d.ts.map