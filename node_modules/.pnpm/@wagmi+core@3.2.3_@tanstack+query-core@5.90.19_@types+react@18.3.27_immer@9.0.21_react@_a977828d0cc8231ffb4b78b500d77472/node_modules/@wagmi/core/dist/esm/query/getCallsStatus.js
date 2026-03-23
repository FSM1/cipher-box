import { getCallsStatus, } from '../actions/getCallsStatus.js';
import { filterQueryOptions } from '../query/utils.js';
export function getCallsStatusQueryOptions(config, options) {
    return {
        ...options.query,
        enabled: Boolean(options.connector?.getProvider && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            if (!options.connector?.getProvider)
                throw new Error('connector is required');
            const [, { connectorUid: _, scopeKey: __, ...parameters }] = context.queryKey;
            const status = await getCallsStatus(config, parameters);
            return status;
        },
        queryKey: getCallsStatusQueryKey(options),
    };
}
export function getCallsStatusQueryKey(options) {
    return ['callsStatus', filterQueryOptions(options)];
}
//# sourceMappingURL=getCallsStatus.js.map