import { simulateContract, } from '../actions/simulateContract.js';
import { filterQueryOptions } from './utils.js';
export function simulateContractQueryOptions(config, options = {}) {
    return {
        ...options.query,
        enabled: Boolean(options.abi &&
            options.address &&
            options.connector &&
            options.functionName &&
            (options.query?.enabled ?? true)),
        queryFn: async (context) => {
            if (!options.abi)
                throw new Error('abi is required');
            if (!options.connector)
                throw new Error('connector is required');
            const [, { scopeKey: _, ...parameters }] = context.queryKey;
            if (!parameters.address)
                throw new Error('address is required');
            if (!parameters.functionName)
                throw new Error('functionName is required');
            return simulateContract(config, {
                ...parameters,
                abi: options.abi,
                address: parameters.address,
                connector: options.connector,
                functionName: parameters.functionName,
            });
        },
        queryKey: simulateContractQueryKey(options),
    };
}
export function simulateContractQueryKey(options = {}) {
    const { connector: _, ...rest } = options;
    return ['simulateContract', filterQueryOptions(rest)];
}
//# sourceMappingURL=simulateContract.js.map