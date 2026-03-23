import { readContract, } from '../actions/readContract.js';
import { filterQueryOptions, structuralSharing } from './utils.js';
export function readContractQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(Boolean(options.address || ('code' in options && options.code)) &&
            options.abi &&
            options.functionName &&
            (options.query?.enabled ?? true)),
        // TODO: Support `signal` once Viem actions allow passthrough
        // https://tkdodo.eu/blog/why-you-want-react-query#bonus-cancellation
        queryFn: async (context) => {
            if (!options.abi)
                throw new Error('abi is required');
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.functionName)
                throw new Error('functionName is required');
            const result = await readContract(config, {
                ...parameters,
                abi: options.abi,
                address: parameters.address,
                code: 'code' in parameters && parameters.code ? parameters.code : undefined,
                functionName: parameters.functionName,
            });
            return result;
        },
        queryKey: readContractQueryKey(options),
        structuralSharing,
    };
}
export function readContractQueryKey(options = {}) {
    return ['readContract', filterQueryOptions(options)];
}
//# sourceMappingURL=readContract.js.map