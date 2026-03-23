import { getConnectorClient, } from '../actions/getConnectorClient.js';
import { filterQueryOptions } from './utils.js';
export function getConnectorClientQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.connector?.getProvider && (options.query?.enabled ?? true)),
        gcTime: 0,
        queryFn: async (context) => {
            const [, { connectorUid: _, scopeKey: __, ...parameters }] = context.queryKey;
            return getConnectorClient(config, {
                ...parameters,
                connector: options.connector,
            });
        },
        queryKey: getConnectorClientQueryKey(options),
        staleTime: Number.POSITIVE_INFINITY,
    };
}
export function getConnectorClientQueryKey(options = {}) {
    return ['connectorClient', filterQueryOptions(options)];
}
//# sourceMappingURL=getConnectorClient.js.map