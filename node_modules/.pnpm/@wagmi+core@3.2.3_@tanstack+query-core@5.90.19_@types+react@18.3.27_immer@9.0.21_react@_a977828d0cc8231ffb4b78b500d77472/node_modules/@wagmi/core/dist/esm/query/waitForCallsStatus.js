import { waitForCallsStatus, } from '../actions/waitForCallsStatus.js';
import { filterQueryOptions } from '../query/utils.js';
export function waitForCallsStatusQueryOptions(config, options) {
    return {
        ...options.query,
        enabled: Boolean(options.id &&
            options.connector?.getProvider &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            if (!options.connector?.getProvider)
                throw new Error('connector is required');
            const [, { connectorUid: _, scopeKey: __, ...parameters }] = context.queryKey;
            if (!parameters.id)
                throw new Error('id is required');
            const status = await waitForCallsStatus(config, {
                ...parameters,
                id: parameters.id,
            });
            return status;
        },
        queryKey: waitForCallsStatusQueryKey(options),
    };
}
export function waitForCallsStatusQueryKey(options = {}) {
    return ['callsStatus', filterQueryOptions(options)];
}
//# sourceMappingURL=waitForCallsStatus.js.map