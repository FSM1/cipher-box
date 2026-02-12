import { Actions } from 'viem/tempo';
import { getConnectorClient } from '../../actions/getConnectorClient.js';
/**
 * Buys a specific amount of tokens.
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
 * const hash = await Actions.dex.buy(config, {
 *   tokenIn: '0x20c...11',
 *   tokenOut: '0x20c...20',
 *   amountOut: parseUnits('100', 6),
 *   maxAmountIn: parseUnits('105', 6),
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function buy(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.buy(client, parameters);
}
/**
 * Buys a specific amount of tokens.
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
 * const result = await Actions.dex.buySync(config, {
 *   tokenIn: '0x20c...11',
 *   tokenOut: '0x20c...20',
 *   amountOut: parseUnits('100', 6),
 *   maxAmountIn: parseUnits('105', 6),
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt.
 */
export async function buySync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.buySync(client, parameters);
}
/**
 * Cancels an order from the orderbook.
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
 * const hash = await Actions.dex.cancel(config, {
 *   orderId: 123n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function cancel(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.cancel(client, parameters);
}
/**
 * Cancels an order from the orderbook.
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
 * const result = await Actions.dex.cancelSync(config, {
 *   orderId: 123n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function cancelSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.cancelSync(client, parameters);
}
/**
 * Cancels a stale order from the orderbook.
 *
 * A stale order is one where the owner's balance or allowance has dropped
 * below the order amount.
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
 * const hash = await Actions.dex.cancelStale(config, {
 *   orderId: 123n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function cancelStale(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.cancelStale(client, parameters);
}
/**
 * Cancels a stale order from the orderbook and waits for confirmation.
 *
 * A stale order is one where the owner's balance or allowance has dropped
 * below the order amount.
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
 * const result = await Actions.dex.cancelStaleSync(config, {
 *   orderId: 123n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function cancelStaleSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.cancelStaleSync(client, parameters);
}
/**
 * Creates a new trading pair on the DEX.
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
 * const hash = await Actions.dex.createPair(config, {
 *   base: '0x20c...11',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function createPair(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.createPair(client, parameters);
}
/**
 * Creates a new trading pair on the DEX.
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
 * const result = await Actions.dex.createPairSync(config, {
 *   base: '0x20c...11',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function createPairSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.createPairSync(client, parameters);
}
/**
 * Gets a user's token balance on the DEX.
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
 * const balance = await Actions.dex.getBalance(config, {
 *   account: '0x...',
 *   token: '0x20c...11',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The user's token balance on the DEX.
 */
export function getBalance(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.getBalance(client, rest);
}
(function (getBalance) {
    function queryKey(parameters) {
        return ['getBalance', parameters];
    }
    getBalance.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.account && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, { account, ...parameters }] = queryKey;
                if (!account)
                    throw new Error('account is required.');
                return await getBalance(config, { account, ...parameters });
            },
        };
    }
    getBalance.queryOptions = queryOptions;
})(getBalance || (getBalance = {}));
/**
 * Gets the quote for buying a specific amount of tokens.
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
 * const amountIn = await Actions.dex.getBuyQuote(config, {
 *   amountOut: parseUnits('100', 6),
 *   tokenIn: '0x20c...11',
 *   tokenOut: '0x20c...20',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The amount of tokenIn needed to buy the specified amountOut.
 */
export function getBuyQuote(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.getBuyQuote(client, rest);
}
(function (getBuyQuote) {
    function queryKey(parameters) {
        return ['getBuyQuote', parameters];
    }
    getBuyQuote.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.tokenIn &&
                rest.tokenOut &&
                rest.amountOut &&
                (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getBuyQuote(config, parameters);
            },
        };
    }
    getBuyQuote.queryOptions = queryOptions;
})(getBuyQuote || (getBuyQuote = {}));
/**
 * Gets an order's details from the orderbook.
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
 * const order = await Actions.dex.getOrder(config, {
 *   orderId: 123n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The order details.
 */
export function getOrder(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.getOrder(client, rest);
}
(function (getOrder) {
    function queryKey(parameters) {
        return ['getOrder', parameters];
    }
    getOrder.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.orderId !== undefined && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getOrder(config, parameters);
            },
        };
    }
    getOrder.queryOptions = queryOptions;
})(getOrder || (getOrder = {}));
/**
 * Gets orderbook information for a trading pair.
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
 * const book = await Actions.dex.getOrderbook(config, {
 *   base: '0x20c...11',
 *   quote: '0x20c...20',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The orderbook information.
 */
export function getOrderbook(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.getOrderbook(client, rest);
}
(function (getOrderbook) {
    function queryKey(parameters) {
        return ['getOrderbook', parameters];
    }
    getOrderbook.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.base && rest.quote && (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getOrderbook(config, parameters);
            },
        };
    }
    getOrderbook.queryOptions = queryOptions;
})(getOrderbook || (getOrderbook = {}));
/**
 * Gets the price level information at a specific tick.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions, Tick } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempoModerato],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const level = await Actions.dex.getTickLevel(config, {
 *   base: '0x20c...11',
 *   tick: Tick.fromPrice('1.001'),
 *   isBid: true,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The price level information.
 */
export function getTickLevel(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.getTickLevel(client, rest);
}
(function (getTickLevel) {
    function queryKey(parameters) {
        return ['getTickLevel', parameters];
    }
    getTickLevel.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.base &&
                rest.tick !== undefined &&
                rest.isBid !== undefined &&
                (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getTickLevel(config, parameters);
            },
        };
    }
    getTickLevel.queryOptions = queryOptions;
})(getTickLevel || (getTickLevel = {}));
/**
 * Gets the quote for selling a specific amount of tokens.
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
 * const amountOut = await Actions.dex.getSellQuote(config, {
 *   amountIn: parseUnits('100', 6),
 *   tokenIn: '0x20c...11',
 *   tokenOut: '0x20c...20',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The amount of tokenOut received for selling the specified amountIn.
 */
export function getSellQuote(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.getSellQuote(client, rest);
}
(function (getSellQuote) {
    function queryKey(parameters) {
        return ['getSellQuote', parameters];
    }
    getSellQuote.queryKey = queryKey;
    function queryOptions(config, parameters) {
        const { query, ...rest } = parameters;
        return {
            ...query,
            enabled: Boolean(rest.tokenIn &&
                rest.tokenOut &&
                rest.amountIn &&
                (query?.enabled ?? true)),
            queryKey: queryKey(rest),
            async queryFn({ queryKey }) {
                const [, parameters] = queryKey;
                return await getSellQuote(config, parameters);
            },
        };
    }
    getSellQuote.queryOptions = queryOptions;
})(getSellQuote || (getSellQuote = {}));
/**
 * Places a limit order on the orderbook.
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
 * const hash = await Actions.dex.place(config, {
 *   amount: parseUnits('100', 6),
 *   tick: Tick.fromPrice('0.99'),
 *   token: '0x20c...11',
 *   type: 'buy',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function place(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.place(client, parameters);
}
/**
 * Places a flip order that automatically flips when filled.
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
 * const hash = await Actions.dex.placeFlip(config, {
 *   amount: parseUnits('100', 6),
 *   flipTick: Tick.fromPrice('1.01'),
 *   tick: Tick.fromPrice('0.99'),
 *   token: '0x20c...11',
 *   type: 'buy',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function placeFlip(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.placeFlip(client, parameters);
}
/**
 * Places a flip order that automatically flips when filled.
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
 * const result = await Actions.dex.placeFlipSync(config, {
 *   amount: parseUnits('100', 6),
 *   flipTick: Tick.fromPrice('1.01'),
 *   tick: Tick.fromPrice('0.99'),
 *   token: '0x20c...11',
 *   type: 'buy',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function placeFlipSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.placeFlipSync(client, parameters);
}
/**
 * Places a limit order on the orderbook.
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
 * const result = await Actions.dex.placeSync(config, {
 *   amount: parseUnits('100', 6),
 *   tick: Tick.fromPrice('0.99'),
 *   token: '0x20c...11',
 *   type: 'buy',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function placeSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.placeSync(client, parameters);
}
/**
 * Sells a specific amount of tokens.
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
 * const hash = await Actions.dex.sell(config, {
 *   amountIn: parseUnits('100', 6),
 *   minAmountOut: parseUnits('95', 6),
 *   tokenIn: '0x20c...11',
 *   tokenOut: '0x20c...20',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function sell(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.sell(client, parameters);
}
/**
 * Sells a specific amount of tokens.
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
 * const result = await Actions.dex.sellSync(config, {
 *   amountIn: parseUnits('100', 6),
 *   minAmountOut: parseUnits('95', 6),
 *   tokenIn: '0x20c...11',
 *   tokenOut: '0x20c...20',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt.
 */
export async function sellSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.sellSync(client, parameters);
}
/**
 * Watches for flip order placement events on the DEX.
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
 * const unwatch = Actions.dex.watchFlipOrderPlaced(config, {
 *   onFlipOrderPlaced: (args, log) => {
 *     console.log('Flip order placed:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchFlipOrderPlaced(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.watchFlipOrderPlaced(client, rest);
}
/**
 * Watches for order cancellation events on the DEX.
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
 * const unwatch = Actions.dex.watchOrderCancelled(config, {
 *   onOrderCancelled: (args, log) => {
 *     console.log('Order cancelled:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchOrderCancelled(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.watchOrderCancelled(client, rest);
}
/**
 * Watches for order filled events on the DEX.
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
 * const unwatch = Actions.dex.watchOrderFilled(config, {
 *   onOrderFilled: (args, log) => {
 *     console.log('Order filled:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchOrderFilled(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.watchOrderFilled(client, rest);
}
/**
 * Watches for order placement events on the DEX.
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
 * const unwatch = Actions.dex.watchOrderPlaced(config, {
 *   onOrderPlaced: (args, log) => {
 *     console.log('Order placed:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export function watchOrderPlaced(config, parameters) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    return Actions.dex.watchOrderPlaced(client, rest);
}
/**
 * Withdraws tokens from the DEX to the caller's wallet.
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
 * const hash = await Actions.dex.withdraw(config, {
 *   amount: 100n,
 *   token: '0x20c...11',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function withdraw(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.withdraw(client, parameters);
}
/**
 * Withdraws tokens from the DEX to the caller's wallet.
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
 * const result = await Actions.dex.withdrawSync(config, {
 *   amount: 100n,
 *   token: '0x20c...11',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function withdrawSync(config, parameters) {
    const { account, chainId, connector } = parameters;
    const client = await getConnectorClient(config, {
        account,
        assertChainId: false,
        chainId,
        connector,
    });
    return Actions.dex.withdrawSync(client, parameters);
}
//# sourceMappingURL=dex.js.map