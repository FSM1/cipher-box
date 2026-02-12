import { type GetConnectionReturnType } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import type { ConfigParameter } from '../types/properties.js';
export type UseConnectionEffectParameters = Compute<{
    onConnect?(data: Compute<Pick<Extract<GetConnectionReturnType, {
        status: 'connected';
    }>, 'address' | 'addresses' | 'chain' | 'chainId' | 'connector'> & {
        isReconnected: boolean;
    }>): void;
    onDisconnect?(): void;
} & ConfigParameter>;
/** https://wagmi.sh/react/api/hooks/useConnectionEffect */
export declare function useConnectionEffect(parameters?: UseConnectionEffectParameters): void;
//# sourceMappingURL=useConnectionEffect.d.ts.map