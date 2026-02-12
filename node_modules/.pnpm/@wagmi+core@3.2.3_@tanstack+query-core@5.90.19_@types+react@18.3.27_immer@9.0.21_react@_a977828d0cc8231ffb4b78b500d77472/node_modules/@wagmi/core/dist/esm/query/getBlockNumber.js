import { getBlockNumber, } from '../actions/getBlockNumber.js';
import { filterQueryOptions } from './utils.js';
export function getBlockNumberQueryOptions(config, options = {}) {
    return {
        ...options.query,
        gcTime: 0,
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            const blockNumber = await getBlockNumber(config, parameters);
            return blockNumber ?? null;
        },
        queryKey: getBlockNumberQueryKey(options),
    };
}
export function getBlockNumberQueryKey(options = {}) {
    return ['blockNumber', filterQueryOptions(options)];
}
//# sourceMappingURL=getBlockNumber.js.map