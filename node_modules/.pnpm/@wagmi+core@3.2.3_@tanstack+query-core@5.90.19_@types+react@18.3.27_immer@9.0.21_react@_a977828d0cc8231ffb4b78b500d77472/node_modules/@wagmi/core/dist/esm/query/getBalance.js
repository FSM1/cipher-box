import { getBalance, } from '../actions/getBalance.js';
import { filterQueryOptions } from './utils.js';
export function getBalanceQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address)
                throw new Error('address is required');
            const balance = await getBalance(config, {
                ...parameters,
                address: parameters.address,
            });
            return balance ?? null;
        },
        queryKey: getBalanceQueryKey(options),
    };
}
export function getBalanceQueryKey(options = {}) {
    return ['balance', filterQueryOptions(options)];
}
//# sourceMappingURL=getBalance.js.map