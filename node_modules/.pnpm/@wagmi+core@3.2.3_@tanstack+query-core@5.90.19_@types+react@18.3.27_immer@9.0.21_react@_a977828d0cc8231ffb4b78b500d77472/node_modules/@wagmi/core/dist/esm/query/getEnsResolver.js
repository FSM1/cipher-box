import { getEnsResolver, } from '../actions/getEnsResolver.js';
import { filterQueryOptions } from './utils.js';
export function getEnsResolverQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.name && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.name)
                throw new Error('name is required');
            return getEnsResolver(config, { ...parameters, name: parameters.name });
        },
        queryKey: getEnsResolverQueryKey(options),
    };
}
export function getEnsResolverQueryKey(options = {}) {
    return ['ensResolver', filterQueryOptions(options)];
}
//# sourceMappingURL=getEnsResolver.js.map