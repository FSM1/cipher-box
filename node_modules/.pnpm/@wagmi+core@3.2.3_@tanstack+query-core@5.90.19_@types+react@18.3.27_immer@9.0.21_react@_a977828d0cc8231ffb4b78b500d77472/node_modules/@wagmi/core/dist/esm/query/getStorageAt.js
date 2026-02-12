import { getStorageAt, } from '../actions/getStorageAt.js';
import { filterQueryOptions } from './utils.js';
export function getStorageAtQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address && options.slot && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address || !parameters.slot)
                throw new Error('address and slot are required');
            return getStorageAt(config, {
                ...parameters,
                address: parameters.address,
                slot: parameters.slot,
            });
        },
        queryKey: getStorageAtQueryKey(options),
    };
}
export function getStorageAtQueryKey(options = {}) {
    return ['getStorageAt', filterQueryOptions(options)];
}
//# sourceMappingURL=getStorageAt.js.map