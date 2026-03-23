import { getBytecode, } from '../actions/getBytecode.js';
import { filterQueryOptions } from './utils.js';
export function getBytecodeQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.address && (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address)
                throw new Error('address is required');
            const bytecode = await getBytecode(config, {
                ...parameters,
                address: parameters.address,
            });
            return (bytecode ?? null);
        },
        queryKey: getBytecodeQueryKey(options),
    };
}
export function getBytecodeQueryKey(options = {}) {
    return ['getBytecode', filterQueryOptions(options)];
}
//# sourceMappingURL=getBytecode.js.map