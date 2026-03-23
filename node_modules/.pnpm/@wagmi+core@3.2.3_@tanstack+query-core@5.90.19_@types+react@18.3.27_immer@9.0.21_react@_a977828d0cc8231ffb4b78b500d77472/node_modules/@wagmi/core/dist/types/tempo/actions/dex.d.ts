import type { Account, BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter, ConnectorParameter } from '../../types/properties.js';
import type { PartialBy, UnionLooseOmit } from '../../types/utils.js';
import type { QueryOptions, QueryParameter } from './utils.js';
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
export declare function buy<config extends Config>(config: config, parameters: buy.Parameters<config>): Promise<Actions.dex.buy.ReturnValue>;
export declare namespace buy {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.buy.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.buy.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function buySync<config extends Config>(config: config, parameters: buySync.Parameters<config>): Promise<Actions.dex.buySync.ReturnValue>;
export declare namespace buySync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.buySync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.buySync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function cancel<config extends Config>(config: config, parameters: cancel.Parameters<config>): Promise<Actions.dex.cancel.ReturnValue>;
export declare namespace cancel {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.cancel.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.cancel.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function cancelSync<config extends Config>(config: config, parameters: cancelSync.Parameters<config>): Promise<Actions.dex.cancelSync.ReturnValue>;
export declare namespace cancelSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.cancelSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.cancelSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function cancelStale<config extends Config>(config: config, parameters: cancelStale.Parameters<config>): Promise<Actions.dex.cancelStale.ReturnValue>;
export declare namespace cancelStale {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.cancelStale.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.cancelStale.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function cancelStaleSync<config extends Config>(config: config, parameters: cancelStaleSync.Parameters<config>): Promise<Actions.dex.cancelStaleSync.ReturnValue>;
export declare namespace cancelStaleSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.cancelStaleSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.cancelStaleSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function createPair<config extends Config>(config: config, parameters: createPair.Parameters<config>): Promise<Actions.dex.createPair.ReturnValue>;
export declare namespace createPair {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.createPair.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.createPair.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function createPairSync<config extends Config>(config: config, parameters: createPairSync.Parameters<config>): Promise<Actions.dex.createPairSync.ReturnValue>;
export declare namespace createPairSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.createPairSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.createPairSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function getBalance<config extends Config>(config: config, parameters: getBalance.Parameters<config>): Promise<getBalance.ReturnValue>;
export declare namespace getBalance {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.getBalance.Parameters;
    type ReturnValue = Actions.dex.getBalance.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: PartialBy<Parameters<config>, 'account'>): readonly ["getBalance", PartialBy<Parameters<config>, "account">];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getBalance.ReturnValue> = PartialBy<getBalance.Parameters<config>, 'account'> & QueryParameter<getBalance.ReturnValue, getBalance.ErrorType, selectData, getBalance.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getBalance.ReturnValue> = QueryOptions<getBalance.ReturnValue, getBalance.ErrorType, selectData, getBalance.QueryKey<config>>;
    }
}
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
export declare function getBuyQuote<config extends Config>(config: config, parameters: getBuyQuote.Parameters<config>): Promise<getBuyQuote.ReturnValue>;
export declare namespace getBuyQuote {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.getBuyQuote.Parameters;
    type ReturnValue = Actions.dex.getBuyQuote.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getBuyQuote", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getBuyQuote.ReturnValue> = getBuyQuote.Parameters<config> & QueryParameter<getBuyQuote.ReturnValue, getBuyQuote.ErrorType, selectData, getBuyQuote.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getBuyQuote.ReturnValue> = QueryOptions<getBuyQuote.ReturnValue, getBuyQuote.ErrorType, selectData, getBuyQuote.QueryKey<config>>;
    }
}
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
export declare function getOrder<config extends Config>(config: config, parameters: getOrder.Parameters<config>): Promise<getOrder.ReturnValue>;
export declare namespace getOrder {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.getOrder.Parameters;
    type ReturnValue = Actions.dex.getOrder.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getOrder", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getOrder.ReturnValue> = getOrder.Parameters<config> & QueryParameter<getOrder.ReturnValue, getOrder.ErrorType, selectData, getOrder.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getOrder.ReturnValue> = QueryOptions<getOrder.ReturnValue, getOrder.ErrorType, selectData, getOrder.QueryKey<config>>;
    }
}
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
export declare function getOrderbook<config extends Config>(config: config, parameters: getOrderbook.Parameters<config>): Promise<getOrderbook.ReturnValue>;
export declare namespace getOrderbook {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.getOrderbook.Parameters;
    type ReturnValue = Actions.dex.getOrderbook.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getOrderbook", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getOrderbook.ReturnValue> = getOrderbook.Parameters<config> & QueryParameter<getOrderbook.ReturnValue, getOrderbook.ErrorType, selectData, getOrderbook.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getOrderbook.ReturnValue> = QueryOptions<getOrderbook.ReturnValue, getOrderbook.ErrorType, selectData, getOrderbook.QueryKey<config>>;
    }
}
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
export declare function getTickLevel<config extends Config>(config: config, parameters: getTickLevel.Parameters<config>): Promise<getTickLevel.ReturnValue>;
export declare namespace getTickLevel {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.getTickLevel.Parameters;
    type ReturnValue = Actions.dex.getTickLevel.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getTickLevel", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getTickLevel.ReturnValue> = getTickLevel.Parameters<config> & QueryParameter<getTickLevel.ReturnValue, getTickLevel.ErrorType, selectData, getTickLevel.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getTickLevel.ReturnValue> = QueryOptions<getTickLevel.ReturnValue, getTickLevel.ErrorType, selectData, getTickLevel.QueryKey<config>>;
    }
}
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
export declare function getSellQuote<config extends Config>(config: config, parameters: getSellQuote.Parameters<config>): Promise<getSellQuote.ReturnValue>;
export declare namespace getSellQuote {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.getSellQuote.Parameters;
    type ReturnValue = Actions.dex.getSellQuote.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getSellQuote", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getSellQuote.ReturnValue> = getSellQuote.Parameters<config> & QueryParameter<getSellQuote.ReturnValue, getSellQuote.ErrorType, selectData, getSellQuote.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getSellQuote.ReturnValue> = QueryOptions<getSellQuote.ReturnValue, getSellQuote.ErrorType, selectData, getSellQuote.QueryKey<config>>;
    }
}
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
export declare function place<config extends Config>(config: config, parameters: place.Parameters<config>): Promise<Actions.dex.place.ReturnValue>;
export declare namespace place {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.place.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.place.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function placeFlip<config extends Config>(config: config, parameters: placeFlip.Parameters<config>): Promise<Actions.dex.placeFlip.ReturnValue>;
export declare namespace placeFlip {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.placeFlip.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.placeFlip.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function placeFlipSync<config extends Config>(config: config, parameters: placeFlipSync.Parameters<config>): Promise<Actions.dex.placeFlipSync.ReturnValue>;
export declare namespace placeFlipSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.placeFlipSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.placeFlipSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function placeSync<config extends Config>(config: config, parameters: placeSync.Parameters<config>): Promise<Actions.dex.placeSync.ReturnValue>;
export declare namespace placeSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.placeSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.placeSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function sell<config extends Config>(config: config, parameters: sell.Parameters<config>): Promise<Actions.dex.sell.ReturnValue>;
export declare namespace sell {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.sell.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.sell.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function sellSync<config extends Config>(config: config, parameters: sellSync.Parameters<config>): Promise<Actions.dex.sellSync.ReturnValue>;
export declare namespace sellSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.sellSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.sellSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function watchFlipOrderPlaced<config extends Config>(config: config, parameters: watchFlipOrderPlaced.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchFlipOrderPlaced {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.watchFlipOrderPlaced.Parameters;
    type Args = Actions.dex.watchFlipOrderPlaced.Args;
    type Log = Actions.dex.watchFlipOrderPlaced.Log;
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
export declare function watchOrderCancelled<config extends Config>(config: config, parameters: watchOrderCancelled.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchOrderCancelled {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.watchOrderCancelled.Parameters;
    type Args = Actions.dex.watchOrderCancelled.Args;
    type Log = Actions.dex.watchOrderCancelled.Log;
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
export declare function watchOrderFilled<config extends Config>(config: config, parameters: watchOrderFilled.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchOrderFilled {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.watchOrderFilled.Parameters;
    type Args = Actions.dex.watchOrderFilled.Args;
    type Log = Actions.dex.watchOrderFilled.Log;
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
export declare function watchOrderPlaced<config extends Config>(config: config, parameters: watchOrderPlaced.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchOrderPlaced {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.dex.watchOrderPlaced.Parameters;
    type Args = Actions.dex.watchOrderPlaced.Args;
    type Log = Actions.dex.watchOrderPlaced.Log;
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
export declare function withdraw<config extends Config>(config: config, parameters: withdraw.Parameters<config>): Promise<Actions.dex.withdraw.ReturnValue>;
export declare namespace withdraw {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.withdraw.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.withdraw.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function withdrawSync<config extends Config>(config: config, parameters: withdrawSync.Parameters<config>): Promise<Actions.dex.withdrawSync.ReturnValue>;
export declare namespace withdrawSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.dex.withdrawSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.dex.withdrawSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
//# sourceMappingURL=dex.d.ts.map