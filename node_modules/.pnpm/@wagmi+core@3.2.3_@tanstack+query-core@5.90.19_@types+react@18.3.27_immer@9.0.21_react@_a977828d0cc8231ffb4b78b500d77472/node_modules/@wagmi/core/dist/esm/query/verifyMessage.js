import { verifyMessage, } from '../actions/verifyMessage.js';
import { filterQueryOptions } from './utils.js';
export function verifyMessageQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address &&
            options.message &&
            options.signature &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address)
                throw new Error('address is required');
            if (!parameters.message)
                throw new Error('message is required');
            if (!parameters.signature)
                throw new Error('signature is required');
            const verified = await verifyMessage(config, {
                ...parameters,
                address: parameters.address,
                message: parameters.message,
                signature: parameters.signature,
            });
            return verified ?? null;
        },
        queryKey: verifyMessageQueryKey(options),
    };
}
export function verifyMessageQueryKey(options = {}) {
    return ['verifyMessage', filterQueryOptions(options)];
}
//# sourceMappingURL=verifyMessage.js.map