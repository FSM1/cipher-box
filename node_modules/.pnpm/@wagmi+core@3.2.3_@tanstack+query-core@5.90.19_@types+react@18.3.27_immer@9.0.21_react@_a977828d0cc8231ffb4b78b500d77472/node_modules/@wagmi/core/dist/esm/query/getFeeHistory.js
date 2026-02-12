import { getFeeHistory, } from '../actions/getFeeHistory.js';
import { filterQueryOptions } from './utils.js';
export function getFeeHistoryQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.blockCount &&
            options.rewardPercentiles &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.blockCount)
                throw new Error('blockCount is required');
            if (!parameters.rewardPercentiles)
                throw new Error('rewardPercentiles is required');
            const feeHistory = await getFeeHistory(config, {
                ...parameters,
                blockCount: parameters.blockCount,
                rewardPercentiles: parameters.rewardPercentiles,
            });
            return feeHistory ?? null;
        },
        queryKey: getFeeHistoryQueryKey(options),
    };
}
export function getFeeHistoryQueryKey(options = {}) {
    return ['feeHistory', filterQueryOptions(options)];
}
//# sourceMappingURL=getFeeHistory.js.map