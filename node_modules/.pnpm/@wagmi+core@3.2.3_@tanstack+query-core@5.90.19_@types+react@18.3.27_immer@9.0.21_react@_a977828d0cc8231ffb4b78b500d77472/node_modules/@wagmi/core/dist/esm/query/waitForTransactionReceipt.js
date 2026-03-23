import { waitForTransactionReceipt, } from '../actions/waitForTransactionReceipt.js';
import { filterQueryOptions } from './utils.js';
export function waitForTransactionReceiptQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.hash && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.hash)
                throw new Error('hash is required');
            return waitForTransactionReceipt(config, {
                ...parameters,
                onReplaced: options.onReplaced,
                hash: parameters.hash,
            });
        },
        queryKey: waitForTransactionReceiptQueryKey(options),
    };
}
export function waitForTransactionReceiptQueryKey(options = {}) {
    const { onReplaced: _, ...rest } = options;
    return ['waitForTransactionReceipt', filterQueryOptions(rest)];
}
//# sourceMappingURL=waitForTransactionReceipt.js.map