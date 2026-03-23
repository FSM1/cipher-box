import type { Account, BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter, ConnectorParameter } from '../../types/properties.js';
import type { UnionLooseOmit } from '../../types/utils.js';
import type { QueryOptions, QueryParameter } from './utils.js';
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
export declare function create<config extends Config>(config: config, parameters: create.Parameters<config>): Promise<Actions.policy.create.ReturnValue>;
export declare namespace create {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.create.Parameters<config['chains'][number], Account>, 'chain' | 'admin'>;
    type ReturnValue = Actions.policy.create.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function createSync<config extends Config>(config: config, parameters: createSync.Parameters<config>): Promise<Actions.policy.createSync.ReturnValue>;
export declare namespace createSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.createSync.Parameters<config['chains'][number], Account>, 'chain' | 'admin'>;
    type ReturnValue = Actions.policy.createSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function setAdmin<config extends Config>(config: config, parameters: setAdmin.Parameters<config>): Promise<Actions.policy.setAdmin.ReturnValue>;
export declare namespace setAdmin {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.setAdmin.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.policy.setAdmin.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function setAdminSync<config extends Config>(config: config, parameters: setAdminSync.Parameters<config>): Promise<Actions.policy.setAdminSync.ReturnValue>;
export declare namespace setAdminSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.setAdminSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.policy.setAdminSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function modifyWhitelist<config extends Config>(config: config, parameters: modifyWhitelist.Parameters<config>): Promise<Actions.policy.modifyWhitelist.ReturnValue>;
export declare namespace modifyWhitelist {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.modifyWhitelist.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.policy.modifyWhitelist.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function modifyWhitelistSync<config extends Config>(config: config, parameters: modifyWhitelistSync.Parameters<config>): Promise<Actions.policy.modifyWhitelistSync.ReturnValue>;
export declare namespace modifyWhitelistSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.modifyWhitelistSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.policy.modifyWhitelistSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function modifyBlacklist<config extends Config>(config: config, parameters: modifyBlacklist.Parameters<config>): Promise<Actions.policy.modifyBlacklist.ReturnValue>;
export declare namespace modifyBlacklist {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.modifyBlacklist.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.policy.modifyBlacklist.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function modifyBlacklistSync<config extends Config>(config: config, parameters: modifyBlacklistSync.Parameters<config>): Promise<Actions.policy.modifyBlacklistSync.ReturnValue>;
export declare namespace modifyBlacklistSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.policy.modifyBlacklistSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.policy.modifyBlacklistSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function getData<config extends Config>(config: config, parameters: getData.Parameters<config>): Promise<getData.ReturnValue>;
export declare namespace getData {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.policy.getData.Parameters;
    type ReturnValue = Actions.policy.getData.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getData", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getData.ReturnValue> = getData.Parameters<config> & QueryParameter<getData.ReturnValue, getData.ErrorType, selectData, getData.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getData.ReturnValue> = QueryOptions<getData.ReturnValue, getData.ErrorType, selectData, getData.QueryKey<config>>;
    }
}
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
export declare function isAuthorized<config extends Config>(config: config, parameters: isAuthorized.Parameters<config>): Promise<isAuthorized.ReturnValue>;
export declare namespace isAuthorized {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.policy.isAuthorized.Parameters;
    type ReturnValue = Actions.policy.isAuthorized.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["isAuthorized", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = isAuthorized.ReturnValue> = isAuthorized.Parameters<config> & QueryParameter<isAuthorized.ReturnValue, isAuthorized.ErrorType, selectData, isAuthorized.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = isAuthorized.ReturnValue> = QueryOptions<isAuthorized.ReturnValue, isAuthorized.ErrorType, selectData, isAuthorized.QueryKey<config>>;
    }
}
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
export declare function watchCreate<config extends Config>(config: config, parameters: watchCreate.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchCreate {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.policy.watchCreate.Parameters;
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
export declare function watchAdminUpdated<config extends Config>(config: config, parameters: watchAdminUpdated.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchAdminUpdated {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.policy.watchAdminUpdated.Parameters;
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
export declare function watchWhitelistUpdated<config extends Config>(config: config, parameters: watchWhitelistUpdated.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchWhitelistUpdated {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.policy.watchWhitelistUpdated.Parameters;
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
export declare function watchBlacklistUpdated<config extends Config>(config: config, parameters: watchBlacklistUpdated.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchBlacklistUpdated {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.policy.watchBlacklistUpdated.Parameters;
}
//# sourceMappingURL=policy.d.ts.map