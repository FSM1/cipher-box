'use client';
import { getConnection, watchConnection, } from '@wagmi/core';
import { useConfig } from './useConfig.js';
import { useSyncExternalStoreWithTracked } from './useSyncExternalStoreWithTracked.js';
/** https://wagmi.sh/react/api/hooks/useConnection */
export function useConnection(parameters = {}) {
    const config = useConfig(parameters);
    return useSyncExternalStoreWithTracked((onChange) => watchConnection(config, { onChange }), () => getConnection(config));
}
//# sourceMappingURL=useConnection.js.map