import { Actions } from 'viem/tempo';
import { getConnectorClient } from '../../actions/getConnectorClient.js';
/**
 * Claims accumulated rewards for a recipient.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.reward.claim(config, {
 *   token: '0x20c0000000000000000000000000000000000001',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function claim(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.reward.claim(client, parameters);
}
/**
 * Claims accumulated rewards for a recipient and waits for confirmation.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.reward.claimSync(config, {
 *   token: '0x20c0000000000000000000000000000000000001',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt.
 */
export async function claimSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.reward.claimSync(client, parameters);
}
/**
 * Gets the global reward per token value for a token.
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
 * const value = await Actions.reward.getGlobalRewardPerToken(config, {
 *   token: '0x20c0000000000000000000000000000000000001',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The global reward per token value (scaled by 1e18).
 */
export function getGlobalRewardPerToken(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.reward.getGlobalRewardPerToken(client, rest);
}
(function (getGlobalRewardPerToken) {
    function queryKey(parameters) {
        return ['getGlobalRewardPerToken', parameters];
    }
    getGlobalRewardPerToken.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.token && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getGlobalRewardPerToken(config, parameters);
            },
        };
    }
    getGlobalRewardPerToken.queryOptions = queryOptions;
})(getGlobalRewardPerToken || (getGlobalRewardPerToken = {}));
/**
 * Gets the reward information for a specific account.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const info = await Actions.reward.getUserRewardInfo(config, {
 *   token: '0x20c0000000000000000000000000000000000001',
 *   account: '0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The user's reward information (recipient, rewardPerToken, rewardBalance).
 */
export function getUserRewardInfo(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.reward.getUserRewardInfo(client, rest);
}
(function (getUserRewardInfo) {
    function queryKey(parameters) {
        return ['getUserRewardInfo', parameters];
    }
    getUserRewardInfo.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.token && rest.account && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getUserRewardInfo(config, parameters);
            },
        };
    }
    getUserRewardInfo.queryOptions = queryOptions;
})(getUserRewardInfo || (getUserRewardInfo = {}));
/**
 * Sets or changes the reward recipient for a token holder.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.reward.setRecipient(config, {
 *   recipient: '0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC',
 *   token: '0x20c0000000000000000000000000000000000001',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function setRecipient(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.reward.setRecipient(client, parameters);
}
/**
 * Sets or changes the reward recipient for a token holder and waits for confirmation.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.reward.setRecipientSync(config, {
 *   recipient: '0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC',
 *   token: '0x20c0000000000000000000000000000000000001',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function setRecipientSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.reward.setRecipientSync(client, parameters);
}
/**
 * Distributes tokens to opted-in holders.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.reward.distribute(config, {
 *   amount: 100000000000000000000n,
 *   seconds: 86400,
 *   token: '0x20c0000000000000000000000000000000000001',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function distribute(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.reward.distribute(client, parameters);
}
/**
 * Distributes tokens to opted-in holders and waits for confirmation.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.reward.distributeSync(config, {
 *   amount: 100000000000000000000n,
 *   seconds: 86400,
 *   token: '0x20c0000000000000000000000000000000000001',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function distributeSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.reward.distributeSync(client, parameters);
}
/**
 * Watches for reward distributed events.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.reward.watchRewardDistributed(config, {
 *   token: '0x20c0000000000000000000000000000000000001',
 *   onRewardDistributed: (args, log) => {
 *     console.log('Reward distributed:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchRewardDistributed(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.reward.watchRewardDistributed(client, rest);
}
/**
 * Watches for reward recipient set events.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoTestnet],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.reward.watchRewardRecipientSet(config, {
 *   token: '0x20c0000000000000000000000000000000000001',
 *   onRewardRecipientSet: (args, log) => {
 *     console.log('Reward recipient set:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchRewardRecipientSet(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.reward.watchRewardRecipientSet(client, rest);
}
//# sourceMappingURL=reward.js.map