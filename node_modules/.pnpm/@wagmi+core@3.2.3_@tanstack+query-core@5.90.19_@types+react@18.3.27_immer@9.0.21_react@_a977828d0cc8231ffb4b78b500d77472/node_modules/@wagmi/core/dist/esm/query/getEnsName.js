import { getEnsName, } from '../actions/getEnsName.js';
import { filterQueryOptions } from './utils.js';
export function getEnsNameQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address)
                throw new Error('address is required');
            return getEnsName(config, { ...parameters, address: parameters.address });
        },
        queryKey: getEnsNameQueryKey(options),
    };
}
export function getEnsNameQueryKey(options = {}) {
    return ['ensName', filterQueryOptions(options)];
}
//# sourceMappingURL=getEnsName.js.map