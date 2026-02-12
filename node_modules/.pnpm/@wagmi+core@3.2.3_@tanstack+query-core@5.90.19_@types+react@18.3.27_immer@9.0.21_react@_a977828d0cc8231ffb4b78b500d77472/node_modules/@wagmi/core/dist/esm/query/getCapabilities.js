import { getCapabilities, } from '../actions/getCapabilities.js';
import { filterQueryOptions } from '../query/utils.js';
export function getCapabilitiesQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.connector?.getProvider && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            if (!options.connector?.getProvider)
                throw new Error('connector is required');
            const [, { connectorUid: _, scopeKey: __, ...parameters }] = context.queryKey;
            const capabilities = await getCapabilities(config, parameters);
            return capabilities;
        },
        queryKey: getCapabilitiesQueryKey(options),
    };
}
export function getCapabilitiesQueryKey(options = {}) {
    return ['capabilities', filterQueryOptions(options)];
}
//# sourceMappingURL=getCapabilities.js.map