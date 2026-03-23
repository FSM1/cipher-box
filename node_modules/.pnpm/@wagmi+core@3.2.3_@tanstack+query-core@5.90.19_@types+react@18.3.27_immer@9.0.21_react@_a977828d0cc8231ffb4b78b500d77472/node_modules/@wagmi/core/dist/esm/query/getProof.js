import { getProof, } from '../actions/getProof.js';
import { filterQueryOptions } from './utils.js';
export function getProofQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address &&
            options.storageKeys &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address || !parameters.storageKeys)
                throw new Error('address and storageKeys are required');
            return getProof(config, {
                ...parameters,
                address: parameters.address,
                storageKeys: parameters.storageKeys,
            });
        },
        queryKey: getProofQueryKey(options),
    };
}
export function getProofQueryKey(options = {}) {
    return ['getProof', filterQueryOptions(options)];
}
//# sourceMappingURL=getProof.js.map