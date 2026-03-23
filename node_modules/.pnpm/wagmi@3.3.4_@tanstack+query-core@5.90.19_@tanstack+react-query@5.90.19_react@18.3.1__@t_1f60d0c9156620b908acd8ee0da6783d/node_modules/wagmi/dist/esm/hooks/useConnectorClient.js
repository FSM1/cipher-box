'use client';
import { useQueryClient } from '@tanstack/react-query';
import { getConnectorClientQueryOptions, } from '@wagmi/core/query';
import { useEffect, useRef } from 'react';
import { useQuery } from '../utils/query.js';
import { useChainId } from './useChainId.js';
import { useConfig } from './useConfig.js';
import { useConnection } from './useConnection.js';
/** https://wagmi.sh/react/api/hooks/useConnectorClient */
export function useConnectorClient(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const { address, connector } = useConnection({ config });
    const options = getConnectorClientQueryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
        connector: parameters.connector ?? connector,
        query: parameters.query,
    });
    const addressRef = useRef(address);
    const queryClient = useQueryClient();
    // biome-ignore lint/correctness/useExhaustiveDependencies: `queryKey` not required
    useEffect(() => {
        const previousAddress = addressRef.current;
        if (!address && previousAddress) {
            // remove when account is disconnected
            queryClient.removeQueries({ queryKey: options.queryKey });
            addressRef.current = undefined;
        }
        else if (address !== previousAddress) {
            // invalidate when address changes
            queryClient.invalidateQueries({ queryKey: options.queryKey });
            addressRef.current = address;
        }
    }, [address, queryClient]);
    return useQuery(options);
}
//# sourceMappingURL=useConnectorClient.js.map