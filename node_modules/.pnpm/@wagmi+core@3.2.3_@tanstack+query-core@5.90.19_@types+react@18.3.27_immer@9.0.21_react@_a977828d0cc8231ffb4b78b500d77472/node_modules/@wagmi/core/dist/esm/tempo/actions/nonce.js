import { Actions } from 'viem/tempo';
import { filterQueryOptions } from './utils.js';
/**
 * Gets the nonce for an account and nonce key.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const nonce = await Actions.nonce.getNonce(config, {
 *   account: '0x...',
 *   nonceKey: 1n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The nonce value.
 */
export function getNonce(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.nonce.getNonce(client, rest);
}
(function (getNonce) {
    function queryKey(parameters) {
        return ['getNonce', filterQueryOptions(parameters)];
    }
    getNonce.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.account && rest.nonceKey !== undefined && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn(context) {
                const [, { account, nonceKey, ...parameters }] = context.queryKey;
                if (!account)
                    throw new Error('account is required.');
                if (nonceKey === undefined)
                    throw new Error('nonceKey is required.');
                return await getNonce(config, { account, nonceKey, ...parameters });
            },
        };
    }
    getNonce.queryOptions = queryOptions;
})(getNonce || (getNonce = {}));
/**
 * Watches for nonce incremented events.
 *
 * @deprecated This function has been deprecated post-AllegroModerato. It will be removed in a future version.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.nonce.watchNonceIncremented(config, {
 *   onNonceIncremented: (args, log) => {
 *     console.log('Nonce incremented:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchNonceIncremented(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.nonce.watchNonceIncremented(client, rest);
}
//# sourceMappingURL=nonce.js.map