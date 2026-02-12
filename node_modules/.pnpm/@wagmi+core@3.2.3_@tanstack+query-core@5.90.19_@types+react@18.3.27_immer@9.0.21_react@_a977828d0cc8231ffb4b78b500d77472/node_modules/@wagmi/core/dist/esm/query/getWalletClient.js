import { getWalletClient, } from '../actions/getWalletClient.js';
import { filterQueryOptions } from './utils.js';
export function getWalletClientQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.connector?.getProvider && (options.query?.enabled ?? true)),
        gcTime: 0,
        queryFn: async (context) => {
            if (!options.connector?.getProvider)
                throw new Error('connector is required');
            const [, { connectorUid: _, scopeKey: __, ...parameters }] = context.queryKey;
            return getWalletClient(config, {
                ...parameters,
                connector: options.connector,
            });
        },
        queryKey: getWalletClientQueryKey(options),
        staleTime: Number.POSITIVE_INFINITY,
    };
}
export function getWalletClientQueryKey(options = {}) {
    return ['walletClient', filterQueryOptions(options)];
}
//# sourceMappingURL=getWalletClient.js.map