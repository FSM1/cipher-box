import type { BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter } from '../../types/properties.js';
import type { UnionCompute } from '../../types/utils.js';
/**
 * Funds an account with an initial amount of set token(s)
 * on Tempo's testnet.
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
 * const hashes = await Actions.faucet.fund(config, {
 *   account: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hashes.
 */
export declare function fund<config extends Config>(config: config, parameters: fund.Parameters<config>): Promise<fund.ReturnValue>;
export declare namespace fund {
    type Parameters<config extends Config> = UnionCompute<ChainIdParameter<config> & Actions.faucet.fund.Parameters>;
    type ReturnValue = Actions.faucet.fund.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Funds an account with an initial amount of set token(s)
 * on Tempo's testnet. Returns with the transaction receipts.
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
 * const receipts = await Actions.faucet.fundSync(config, {
 *   account: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction hashes.
 */
export declare function fundSync<config extends Config>(config: config, parameters: fundSync.Parameters<config>): Promise<fundSync.ReturnValue>;
export declare namespace fundSync {
    type Parameters<config extends Config> = UnionCompute<ChainIdParameter<config> & Actions.faucet.fundSync.Parameters>;
    type ReturnValue = Actions.faucet.fundSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
//# sourceMappingURL=faucet.d.ts.map