import type { Account, BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter, ConnectorParameter } from '../../types/properties.js';
import type { UnionLooseOmit } from '../../types/utils.js';
import type { QueryOptions, QueryParameter } from './utils.js';
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
export declare function claim<config extends Config>(config: config, parameters: claim.Parameters<config>): Promise<Actions.reward.claim.ReturnValue>;
export declare namespace claim {
    type Parameters<config extends Config = Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.reward.claim.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.reward.claim.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function claimSync<config extends Config>(config: config, parameters: claimSync.Parameters<config>): Promise<Actions.reward.claimSync.ReturnValue>;
export declare namespace claimSync {
    type Parameters<config extends Config = Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.reward.claimSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.reward.claimSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function getGlobalRewardPerToken<config extends Config>(config: config, parameters: getGlobalRewardPerToken.Parameters<config>): Promise<getGlobalRewardPerToken.ReturnValue>;
export declare namespace getGlobalRewardPerToken {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.reward.getGlobalRewardPerToken.Parameters;
    type ReturnValue = Actions.reward.getGlobalRewardPerToken.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getGlobalRewardPerToken", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getGlobalRewardPerToken.ReturnValue> = getGlobalRewardPerToken.Parameters<config> & QueryParameter<getGlobalRewardPerToken.ReturnValue, getGlobalRewardPerToken.ErrorType, selectData, getGlobalRewardPerToken.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getGlobalRewardPerToken.ReturnValue> = QueryOptions<getGlobalRewardPerToken.ReturnValue, getGlobalRewardPerToken.ErrorType, selectData, getGlobalRewardPerToken.QueryKey<config>>;
    }
}
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
export declare function getUserRewardInfo<config extends Config>(config: config, parameters: getUserRewardInfo.Parameters<config>): Promise<getUserRewardInfo.ReturnValue>;
export declare namespace getUserRewardInfo {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.reward.getUserRewardInfo.Parameters;
    type ReturnValue = Actions.reward.getUserRewardInfo.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getUserRewardInfo", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getUserRewardInfo.ReturnValue> = getUserRewardInfo.Parameters<config> & QueryParameter<getUserRewardInfo.ReturnValue, getUserRewardInfo.ErrorType, selectData, getUserRewardInfo.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getUserRewardInfo.ReturnValue> = QueryOptions<getUserRewardInfo.ReturnValue, getUserRewardInfo.ErrorType, selectData, getUserRewardInfo.QueryKey<config>>;
    }
}
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
export declare function setRecipient<config extends Config>(config: config, parameters: setRecipient.Parameters<config>): Promise<Actions.reward.setRecipient.ReturnValue>;
export declare namespace setRecipient {
    type Parameters<config extends Config = Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.reward.setRecipient.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.reward.setRecipient.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function setRecipientSync<config extends Config>(config: config, parameters: setRecipientSync.Parameters<config>): Promise<Actions.reward.setRecipientSync.ReturnValue>;
export declare namespace setRecipientSync {
    type Parameters<config extends Config = Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.reward.setRecipientSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.reward.setRecipientSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function distribute<config extends Config>(config: config, parameters: distribute.Parameters<config>): Promise<Actions.reward.distribute.ReturnValue>;
export declare namespace distribute {
    type Parameters<config extends Config = Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.reward.distribute.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.reward.distribute.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function distributeSync<config extends Config>(config: config, parameters: distributeSync.Parameters<config>): Promise<Actions.reward.distributeSync.ReturnValue>;
export declare namespace distributeSync {
    type Parameters<config extends Config = Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.reward.distributeSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.reward.distributeSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function watchRewardDistributed<config extends Config>(config: config, parameters: watchRewardDistributed.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchRewardDistributed {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.reward.watchRewardDistributed.Parameters;
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
export declare function watchRewardRecipientSet<config extends Config>(config: config, parameters: watchRewardRecipientSet.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchRewardRecipientSet {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.reward.watchRewardRecipientSet.Parameters;
}
//# sourceMappingURL=reward.d.ts.map