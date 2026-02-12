import { call, } from '../actions/call.js';
import { filterQueryOptions } from './utils.js';
export function callQueryOptions(config, options = {}) {
    return {
        ...options.query,
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            const data = await call(config, {
                ...parameters,
            });
            return data ?? null;
        },
        queryKey: callQueryKey(options),
    };
}
export function callQueryKey(options = {}) {
    return ['call', filterQueryOptions(options)];
}
//# sourceMappingURL=call.js.map