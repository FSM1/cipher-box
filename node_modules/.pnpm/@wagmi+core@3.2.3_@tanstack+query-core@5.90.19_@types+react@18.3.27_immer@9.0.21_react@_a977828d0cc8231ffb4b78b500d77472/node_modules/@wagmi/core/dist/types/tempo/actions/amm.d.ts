import type { Account, BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter, ConnectorParameter } from '../../types/properties.js';
import type { UnionLooseOmit } from '../../types/utils.js';
import type { QueryOptions, QueryParameter } from './utils.js';
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
export declare function getPool<config extends Config>(config: config, parameters: getPool.Parameters<config>): Promise<getPool.ReturnValue>;
export declare namespace getPool {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.amm.getPool.Parameters;
    type ReturnValue = Actions.amm.getPool.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getPool", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getPool.ReturnValue> = getPool.Parameters<config> & QueryParameter<getPool.ReturnValue, getPool.ErrorType, selectData, getPool.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getPool.ReturnValue> = QueryOptions<getPool.ReturnValue, getPool.ErrorType, selectData, getPool.QueryKey<config>>;
    }
}
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
export declare function getLiquidityBalance<config extends Config>(config: config, parameters: getLiquidityBalance.Parameters<config>): Promise<getLiquidityBalance.ReturnValue>;
export declare namespace getLiquidityBalance {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.amm.getLiquidityBalance.Parameters;
    type ReturnValue = Actions.amm.getLiquidityBalance.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getLiquidityBalance", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getLiquidityBalance.ReturnValue> = getLiquidityBalance.Parameters<config> & QueryParameter<getLiquidityBalance.ReturnValue, getLiquidityBalance.ErrorType, selectData, getLiquidityBalance.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getLiquidityBalance.ReturnValue> = QueryOptions<getLiquidityBalance.ReturnValue, getLiquidityBalance.ErrorType, selectData, getLiquidityBalance.QueryKey<config>>;
    }
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
export declare function rebalanceSwap<config extends Config>(config: config, parameters: rebalanceSwap.Parameters<config>): Promise<Actions.amm.rebalanceSwap.ReturnValue>;
export declare namespace rebalanceSwap {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.amm.rebalanceSwap.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.amm.rebalanceSwap.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function rebalanceSwapSync<config extends Config>(config: config, parameters: rebalanceSwapSync.Parameters<config>): Promise<Actions.amm.rebalanceSwapSync.ReturnValue>;
export declare namespace rebalanceSwapSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.amm.rebalanceSwapSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.amm.rebalanceSwapSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function mint<config extends Config>(config: config, parameters: mint.Parameters<config>): Promise<Actions.amm.mint.ReturnValue>;
export declare namespace mint {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.amm.mint.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.amm.mint.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function mintSync<config extends Config>(config: config, parameters: mintSync.Parameters<config>): Promise<Actions.amm.mintSync.ReturnValue>;
export declare namespace mintSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.amm.mintSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.amm.mintSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function burn<config extends Config>(config: config, parameters: burn.Parameters<config>): Promise<Actions.amm.burn.ReturnValue>;
export declare namespace burn {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.amm.burn.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.amm.burn.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function burnSync<config extends Config>(config: config, parameters: burnSync.Parameters<config>): Promise<Actions.amm.burnSync.ReturnValue>;
export declare namespace burnSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.amm.burnSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.amm.burnSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function watchRebalanceSwap<config extends Config>(config: config, parameters: watchRebalanceSwap.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchRebalanceSwap {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.amm.watchRebalanceSwap.Parameters;
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
export declare function watchMint<config extends Config>(config: config, parameters: watchMint.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchMint {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.amm.watchMint.Parameters;
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
export declare function watchBurn<config extends Config>(config: config, parameters: watchBurn.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchBurn {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.amm.watchBurn.Parameters;
}
//# sourceMappingURL=amm.d.ts.map