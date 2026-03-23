import { estimateFeesPerGas, } from '../actions/estimateFeesPerGas.js';
import { filterQueryOptions } from './utils.js';
export function estimateFeesPerGasQueryOptions(config, options = {}) {
    return {
        ...options.query,
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            return estimateFeesPerGas(config, parameters);
        },
        queryKey: estimateFeesPerGasQueryKey(options),
    };
}
export function estimateFeesPerGasQueryKey(options = {}) {
    return ['estimateFeesPerGas', filterQueryOptions(options)];
}
//# sourceMappingURL=estimateFeesPerGas.js.map