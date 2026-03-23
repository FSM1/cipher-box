import { getTransactionConfirmations, } from '../actions/getTransactionConfirmations.js';
import { filterQueryOptions } from './utils.js';
export function getTransactionConfirmationsQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean((options.hash || options.transactionReceipt) &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.hash && !parameters.transactionReceipt)
                throw new Error('hash or transactionReceipt is required');
            const confirmations = await getTransactionConfirmations(config, {
                ...parameters,
                hash: parameters.hash,
                transactionReceipt: parameters.transactionReceipt,
            });
            return confirmations ?? null;
        },
        queryKey: getTransactionConfirmationsQueryKey(options),
    };
}
export function getTransactionConfirmationsQueryKey(options = {}) {
    return ['transactionConfirmations', filterQueryOptions(options)];
}
//# sourceMappingURL=getTransactionConfirmations.js.map