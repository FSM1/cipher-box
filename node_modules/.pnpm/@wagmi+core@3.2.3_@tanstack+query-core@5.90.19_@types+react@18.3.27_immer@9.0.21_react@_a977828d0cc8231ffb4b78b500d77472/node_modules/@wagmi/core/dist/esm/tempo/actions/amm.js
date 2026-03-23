import { Actions } from 'viem/tempo';
import { getConnectorClient } from '../../actions/getConnectorClient.js';
import { filterQueryOptions } from './utils.js';
/**
 * Gets the reserves for a liquidity pool.
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
 * const pool = await Actions.amm.getPool(config, {
 *   userToken: '0x...',
 *   validatorToken: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The pool reserves.
 */
export function getPool(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.amm.getPool(client, rest);
}
(function (getPool) {
    function queryKey(parameters) {
        return ['getPool', filterQueryOptions(parameters)];
    }
    getPool.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.userToken && rest.validatorToken && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getPool(config, parameters);
            },
        };
    }
    getPool.queryOptions = queryOptions;
})(getPool || (getPool = {}));
/**
 * Gets the LP token balance for an account in a specific pool.
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
 * const poolId = await Actions.amm.getPoolId(config, {
 *   userToken: '0x...',
 *   validatorToken: '0x...',
 * })
 *
 * const balance = await Actions.amm.getLiquidityBalance(config, {
 *   poolId,
 *   address: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The LP token balance.
 */
export function getLiquidityBalance(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.amm.getLiquidityBalance(client, rest);
}
(function (getLiquidityBalance) {
    function queryKey(parameters) {
        return ['getLiquidityBalance', filterQueryOptions(parameters)];
    }
    getLiquidityBalance.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.address &&
                (rest.poolId ||
                    (rest.userToken !== undefined &&
                        rest.validatorToken !== undefined)) &&
                (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getLiquidityBalance(config, parameters);
            },
        };
    }
    getLiquidityBalance.queryOptions = queryOptions;
})(getLiquidityBalance || (getLiquidityBalance = {}));
/**
 * Performs a rebalance swap from validator token to user token.
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
 * const hash = await Actions.amm.rebalanceSwap(config, {
 *   userToken: '0x...',
 *   validatorToken: '0x...',
 *   amountOut: 100n,
 *   to: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function rebalanceSwap(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.amm.rebalanceSwap(client, parameters);
}
/**
 * Performs a rebalance swap from validator token to user token.
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
 * const result = await Actions.amm.rebalanceSwapSync(config, {
 *   userToken: '0x...',
 *   validatorToken: '0x...',
 *   amountOut: 100n,
 *   to: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function rebalanceSwapSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.amm.rebalanceSwapSync(client, parameters);
}
/**
 * Adds liquidity to a pool.
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
 * const hash = await Actions.amm.mint(config, {
 *   userTokenAddress: '0x20c0...beef',
 *   validatorTokenAddress: '0x20c0...babe',
 *   validatorTokenAmount: 100n,
 *   to: '0xfeed...fede',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function mint(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.amm.mint(client, parameters);
}
/**
 * Adds liquidity to a pool.
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
 * const result = await Actions.amm.mintSync(config, {
 *   userTokenAddress: '0x20c0...beef',
 *   validatorTokenAddress: '0x20c0...babe',
 *   validatorTokenAmount: 100n,
 *   to: '0xfeed...fede',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function mintSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.amm.mintSync(client, parameters);
}
/**
 * Removes liquidity from a pool.
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
 * const hash = await Actions.amm.burn(config, {
 *   userToken: '0x20c0...beef',
 *   validatorToken: '0x20c0...babe',
 *   liquidity: 50n,
 *   to: '0xfeed...fede',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function burn(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.amm.burn(client, parameters);
}
/**
 * Removes liquidity from a pool.
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
 * const result = await Actions.amm.burnSync(config, {
 *   userToken: '0x20c0...beef',
 *   validatorToken: '0x20c0...babe',
 *   liquidity: 50n,
 *   to: '0xfeed...fede',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function burnSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.amm.burnSync(client, parameters);
}
/**
 * Watches for rebalance swap events.
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
 * const unwatch = Actions.amm.watchRebalanceSwap(config, {
 *   onRebalanceSwap: (args, log) => {
 *     console.log('Rebalance swap:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchRebalanceSwap(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.amm.watchRebalanceSwap(client, rest);
}
/**
 * Watches for liquidity mint events.
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
 * const unwatch = Actions.amm.watchMint(config, {
 *   onMint: (args, log) => {
 *     console.log('Liquidity added:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchMint(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.amm.watchMint(client, rest);
}
/**
 * Watches for liquidity burn events.
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
 * const unwatch = Actions.amm.watchBurn(config, {
 *   onBurn: (args, log) => {
 *     console.log('Liquidity removed:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchBurn(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.amm.watchBurn(client, rest);
}
//# sourceMappingURL=amm.js.map