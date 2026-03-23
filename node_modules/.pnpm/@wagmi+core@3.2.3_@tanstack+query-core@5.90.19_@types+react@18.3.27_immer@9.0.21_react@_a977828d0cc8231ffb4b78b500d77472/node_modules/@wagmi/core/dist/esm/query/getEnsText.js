import { getEnsText, } from '../actions/getEnsText.js';
import { filterQueryOptions } from './utils.js';
export function getEnsTextQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.key && options.name && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.key || !parameters.name)
                throw new Error('key and name are required');
            return getEnsText(config, {
                ...parameters,
                key: parameters.key,
                name: parameters.name,
            });
        },
        queryKey: getEnsTextQueryKey(options),
    };
}
export function getEnsTextQueryKey(options = {}) {
    return ['ensText', filterQueryOptions(options)];
}
//# sourceMappingURL=getEnsText.js.map