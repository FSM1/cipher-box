import { Actions } from 'viem/tempo';
import { getConnectorClient } from '../../actions/getConnectorClient.js';
/**
 * Creates a new policy.
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
 * const hash = await Actions.policy.create(config, {
 *   type: 'whitelist',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export async function create(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.create(client, parameters);
}
/**
 * Creates a new policy.
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
 * const result = await Actions.policy.createSync(config, {
 *   type: 'whitelist',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function createSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.createSync(client, parameters);
}
/**
 * Sets the admin for a policy.
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
 * const hash = await Actions.policy.setAdmin(config, {
 *   policyId: 2n,
 *   admin: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export async function setAdmin(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.setAdmin(client, parameters);
}
/**
 * Sets the admin for a policy.
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
 * const result = await Actions.policy.setAdminSync(config, {
 *   policyId: 2n,
 *   admin: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function setAdminSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.setAdminSync(client, parameters);
}
/**
 * Modifies a policy whitelist.
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
 * const hash = await Actions.policy.modifyWhitelist(config, {
 *   policyId: 2n,
 *   address: '0x...',
 *   allowed: true,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export async function modifyWhitelist(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.modifyWhitelist(client, parameters);
}
/**
 * Modifies a policy whitelist.
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
 * const result = await Actions.policy.modifyWhitelistSync(config, {
 *   policyId: 2n,
 *   address: '0x...',
 *   allowed: true,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function modifyWhitelistSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.modifyWhitelistSync(client, parameters);
}
/**
 * Modifies a policy blacklist.
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
 * const hash = await Actions.policy.modifyBlacklist(config, {
 *   policyId: 2n,
 *   address: '0x...',
 *   restricted: true,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export async function modifyBlacklist(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.modifyBlacklist(client, parameters);
}
/**
 * Modifies a policy blacklist.
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
 * const result = await Actions.policy.modifyBlacklistSync(config, {
 *   policyId: 2n,
 *   address: '0x...',
 *   restricted: true,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function modifyBlacklistSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.policy.modifyBlacklistSync(client, parameters);
}
/**
 * Gets policy data.
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
 * const data = await Actions.policy.getData(config, {
 *   policyId: 2n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The policy data.
 */
export function getData(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.policy.getData(client, rest);
}
(function (getData) {
    function queryKey(parameters) {
        return ['getData', parameters];
    }
    getData.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.policyId !== undefined && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getData(config, parameters);
            },
        };
    }
    getData.queryOptions = queryOptions;
})(getData || (getData = {}));
/**
 * Checks if a user is authorized by a policy.
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
 * const authorized = await Actions.policy.isAuthorized(config, {
 *   policyId: 2n,
 *   user: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Whether the user is authorized.
 */
export function isAuthorized(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.policy.isAuthorized(client, rest);
}
(function (isAuthorized) {
    function queryKey(parameters) {
        return ['isAuthorized', parameters];
    }
    isAuthorized.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.policyId !== undefined && rest.user && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await isAuthorized(config, parameters);
            },
        };
    }
    isAuthorized.queryOptions = queryOptions;
})(isAuthorized || (isAuthorized = {}));
/**
 * Watches for policy creation events.
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
 * const unwatch = Actions.policy.watchCreate(config, {
 *   onPolicyCreated: (args, log) => {
 *     console.log('Policy created:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchCreate(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.policy.watchCreate(client, rest);
}
/**
 * Watches for policy admin update events.
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
 * const unwatch = Actions.policy.watchAdminUpdated(config, {
 *   onAdminUpdated: (args, log) => {
 *     console.log('Policy admin updated:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchAdminUpdated(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.policy.watchAdminUpdated(client, rest);
}
/**
 * Watches for whitelist update events.
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
 * const unwatch = Actions.policy.watchWhitelistUpdated(config, {
 *   onWhitelistUpdated: (args, log) => {
 *     console.log('Whitelist updated:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchWhitelistUpdated(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.policy.watchWhitelistUpdated(client, rest);
}
/**
 * Watches for blacklist update events.
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
 * const unwatch = Actions.policy.watchBlacklistUpdated(config, {
 *   onBlacklistUpdated: (args, log) => {
 *     console.log('Blacklist updated:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchBlacklistUpdated(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.policy.watchBlacklistUpdated(client, rest);
}
//# sourceMappingURL=policy.js.map