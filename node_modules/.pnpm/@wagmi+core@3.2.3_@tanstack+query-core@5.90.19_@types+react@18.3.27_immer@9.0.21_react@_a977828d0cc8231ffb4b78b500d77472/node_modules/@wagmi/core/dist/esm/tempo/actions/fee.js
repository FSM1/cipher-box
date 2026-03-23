import { Actions } from 'viem/tempo';
import { getConnectorClient } from '../../actions/getConnectorClient.js';
import { filterQueryOptions } from './utils.js';
/**
 * Gets the user's default fee token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoModerato],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.fee.getUserToken(config, {
 *   account: '0x20c...0055',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export function getUserToken(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.fee.getUserToken(client, rest);
}
(function (getUserToken) {
    function queryKey(parameters) {
        return ['getUserToken', filterQueryOptions(parameters)];
    }
    getUserToken.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.account && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn(context) {
                const [, { account, ...parameters }] = context.queryKey;
                if (!account)
                    throw new Error('account is required.');
                return await getUserToken(config, { account, ...parameters });
            },
        };
    }
    getUserToken.queryOptions = queryOptions;
})(getUserToken || (getUserToken = {}));
/**
 * Sets the user's default fee token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoModerato],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.fee.setUserToken(config, {
 *   token: '0x20c...0055',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function setUserToken(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.fee.setUserToken(client, parameters);
}
/**
 * Sets the user's default fee token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoModerato],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.fee.setUserTokenSync(config, {
 *   token: '0x20c...0055',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function setUserTokenSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.fee.setUserTokenSync(client, parameters);
}
/**
 * Watches for user token set events on the Fee Manager.
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
 * const unwatch = Actions.fee.watchSetUserToken(config, {
 *   onUserTokenSet: (args, log) => {
 *     console.log('User token set:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchSetUserToken(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.fee.watchSetUserToken(client, rest);
}
//# sourceMappingURL=fee.js.map