import { estimateMaxPriorityFeePerGas, } from '../actions/estimateMaxPriorityFeePerGas.js';
import { filterQueryOptions } from './utils.js';
export function estimateMaxPriorityFeePerGasQueryOptions(config, options = {}) {
    return {
        ...options.query,
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            return estimateMaxPriorityFeePerGas(config, parameters);
        },
        queryKey: estimateMaxPriorityFeePerGasQueryKey(options),
    };
}
export function estimateMaxPriorityFeePerGasQueryKey(options = {}) {
    return ['estimateMaxPriorityFeePerGas', filterQueryOptions(options)];
}
//# sourceMappingURL=estimateMaxPriorityFeePerGas.js.map