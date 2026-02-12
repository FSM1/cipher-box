import type { Account, BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter, ConnectorParameter } from '../../types/properties.js';
import type { PartialBy, UnionLooseOmit } from '../../types/utils.js';
import type { QueryOptions, QueryParameter } from './utils.js';
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
export declare function getUserToken<config extends Config>(config: config, parameters: getUserToken.Parameters<config>): Promise<getUserToken.ReturnValue>;
export declare namespace getUserToken {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.fee.getUserToken.Parameters;
    type ReturnValue = Actions.fee.getUserToken.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: PartialBy<Parameters<config>, 'account'>): readonly ["getUserToken", PartialBy<Parameters<config>, "account">];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getUserToken.ReturnValue> = PartialBy<getUserToken.Parameters<config>, 'account'> & QueryParameter<getUserToken.ReturnValue, getUserToken.ErrorType, selectData, getUserToken.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getUserToken.ReturnValue> = QueryOptions<getUserToken.ReturnValue, getUserToken.ErrorType, selectData, getUserToken.QueryKey<config>>;
    }
}
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
export declare function setUserToken<config extends Config>(config: config, parameters: setUserToken.Parameters<config>): Promise<Actions.fee.setUserToken.ReturnValue>;
export declare namespace setUserToken {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.fee.setUserToken.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.fee.setUserToken.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function setUserTokenSync<config extends Config>(config: config, parameters: setUserTokenSync.Parameters<config>): Promise<Actions.fee.setUserTokenSync.ReturnValue>;
export declare namespace setUserTokenSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.fee.setUserTokenSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.fee.setUserTokenSync.ReturnValue;
    type ErrorType = BaseErrorType;
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
export declare function watchSetUserToken<config extends Config>(config: config, parameters: watchSetUserToken.Parameters<config>): () => void;
export declare namespace watchSetUserToken {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.fee.watchSetUserToken.Parameters;
}
//# sourceMappingURL=fee.d.ts.map