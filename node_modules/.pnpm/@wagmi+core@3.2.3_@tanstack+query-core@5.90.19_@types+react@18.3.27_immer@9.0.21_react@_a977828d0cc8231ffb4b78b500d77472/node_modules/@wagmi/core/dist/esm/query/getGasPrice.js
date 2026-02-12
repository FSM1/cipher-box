import { getGasPrice, } from '../actions/getGasPrice.js';
import { filterQueryOptions } from './utils.js';
export function getGasPriceQueryOptions(config, options = {}) {
    return {
        ...options.query,
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            const gasPrice = await getGasPrice(config, parameters);
            return gasPrice ?? null;
        },
        queryKey: getGasPriceQueryKey(options),
    };
}
export function getGasPriceQueryKey(options = {}) {
    return ['gasPrice', filterQueryOptions(options)];
}
//# sourceMappingURL=getGasPrice.js.map