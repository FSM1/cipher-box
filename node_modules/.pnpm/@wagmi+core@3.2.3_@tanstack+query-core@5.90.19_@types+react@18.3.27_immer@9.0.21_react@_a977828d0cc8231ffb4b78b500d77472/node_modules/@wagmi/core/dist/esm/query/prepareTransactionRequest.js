import { prepareTransactionRequest, } from '../actions/prepareTransactionRequest.js';
import { filterQueryOptions } from './utils.js';
export function prepareTransactionRequestQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.to && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.to)
                throw new Error('to is required');
            return prepareTransactionRequest(config, {
                ...parameters,
                to: parameters.to,
            });
        },
        queryKey: prepareTransactionRequestQueryKey(options),
    };
}
export function prepareTransactionRequestQueryKey(options = {}) {
    return ['prepareTransactionRequest', filterQueryOptions(options)];
}
//# sourceMappingURL=prepareTransactionRequest.js.map