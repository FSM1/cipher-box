import { estimateGas, } from '../actions/estimateGas.js';
import { filterQueryOptions } from './utils.js';
export function estimateGasQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean((options.account || options.connector) &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.account && !options.connector)
                throw new Error('account or connector is required');
            return estimateGas(config, {
                ...parameters,
                account: parameters.account,
                connector: options.connector,
            });
        },
        queryKey: estimateGasQueryKey(options),
    };
}
export function estimateGasQueryKey(options = {}) {
    return ['estimateGas', filterQueryOptions(options)];
}
//# sourceMappingURL=estimateGas.js.map