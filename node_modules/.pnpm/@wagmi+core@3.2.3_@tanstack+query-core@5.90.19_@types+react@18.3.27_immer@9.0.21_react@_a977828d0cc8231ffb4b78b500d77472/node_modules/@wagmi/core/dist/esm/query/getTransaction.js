import { getTransaction, } from '../actions/getTransaction.js';
import { filterQueryOptions } from './utils.js';
export function getTransactionQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean((options.hash ||
            (options.index &&
                (options.blockHash || options.blockNumber || options.blockTag))) &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!(parameters.hash ||
                (parameters.index &&
                    (parameters.blockHash ||
                        parameters.blockNumber ||
                        parameters.blockTag))))
                throw new Error('hash OR index AND blockHash, blockNumber, blockTag is required');
            return getTransaction(config, parameters);
        },
        queryKey: getTransactionQueryKey(options),
    };
}
export function getTransactionQueryKey(options = {}) {
    return ['transaction', filterQueryOptions(options)];
}
//# sourceMappingURL=getTransaction.js.map