import { getTransactionReceipt, } from '../actions/getTransactionReceipt.js';
import { filterQueryOptions } from './utils.js';
export function getTransactionReceiptQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.hash && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.hash)
                throw new Error('hash is required');
            return getTransactionReceipt(config, {
                ...parameters,
                hash: parameters.hash,
            });
        },
        queryKey: getTransactionReceiptQueryKey(options),
    };
}
export function getTransactionReceiptQueryKey(options = {}) {
    return ['getTransactionReceipt', filterQueryOptions(options)];
}
//# sourceMappingURL=getTransactionReceipt.js.map