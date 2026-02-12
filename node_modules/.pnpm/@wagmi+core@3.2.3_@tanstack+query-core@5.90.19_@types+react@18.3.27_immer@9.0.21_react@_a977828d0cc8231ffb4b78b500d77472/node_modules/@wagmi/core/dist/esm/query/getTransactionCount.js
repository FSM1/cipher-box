import { getTransactionCount, } from '../actions/getTransactionCount.js';
import { filterQueryOptions } from './utils.js';
export function getTransactionCountQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address)
                throw new Error('address is required');
            const transactionCount = await getTransactionCount(config, {
                ...parameters,
                address: parameters.address,
            });
            return transactionCount ?? null;
        },
        queryKey: getTransactionCountQueryKey(options),
    };
}
export function getTransactionCountQueryKey(options = {}) {
    return ['transactionCount', filterQueryOptions(options)];
}
//# sourceMappingURL=getTransactionCount.js.map