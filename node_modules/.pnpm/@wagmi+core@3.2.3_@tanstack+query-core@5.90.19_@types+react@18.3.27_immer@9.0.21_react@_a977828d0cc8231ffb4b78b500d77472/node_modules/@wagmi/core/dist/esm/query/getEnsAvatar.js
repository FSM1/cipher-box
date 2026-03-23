import { getEnsAvatar, } from '../actions/getEnsAvatar.js';
import { filterQueryOptions } from './utils.js';
export function getEnsAvatarQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.name && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.name)
                throw new Error('name is required');
            return getEnsAvatar(config, { ...parameters, name: parameters.name });
        },
        queryKey: getEnsAvatarQueryKey(options),
    };
}
export function getEnsAvatarQueryKey(options = {}) {
    return ['ensAvatar', filterQueryOptions(options)];
}
//# sourceMappingURL=getEnsAvatar.js.map