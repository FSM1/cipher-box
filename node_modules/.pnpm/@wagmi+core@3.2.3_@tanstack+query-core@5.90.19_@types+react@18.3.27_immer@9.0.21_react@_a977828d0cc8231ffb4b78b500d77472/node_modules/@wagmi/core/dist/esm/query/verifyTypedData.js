import { verifyTypedData, } from '../actions/verifyTypedData.js';
import { filterQueryOptions } from './utils.js';
export function verifyTypedDataQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address &&
            options.message &&
            options.primaryType &&
            options.signature &&
            options.types &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address)
                throw new Error('address is required');
            if (!parameters.message)
                throw new Error('message is required');
            if (!parameters.primaryType)
                throw new Error('primaryType is required');
            if (!parameters.signature)
                throw new Error('signature is required');
            if (!parameters.types)
                throw new Error('types is required');
            const verified = await verifyTypedData(config, {
                ...parameters,
                address: parameters.address,
                message: parameters.message,
                primaryType: parameters.primaryType,
                signature: parameters.signature,
                types: parameters.types,
            });
            return verified ?? null;
        },
        queryKey: verifyTypedDataQueryKey(options),
    };
}
export function verifyTypedDataQueryKey(options = {}) {
    return ['verifyTypedData', filterQueryOptions(options)];
}
//# sourceMappingURL=verifyTypedData.js.map