import { getEnsAddress, } from '../actions/getEnsAddress.js';
import { filterQueryOptions } from './utils.js';
export function getEnsAddressQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.name && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.name)
                throw new Error('name is required');
            return getEnsAddress(config, { ...parameters, name: parameters.name });
        },
        queryKey: getEnsAddressQueryKey(options),
    };
}
export function getEnsAddressQueryKey(options = {}) {
    return ['ensAddress', filterQueryOptions(options)];
}
//# sourceMappingURL=getEnsAddress.js.map