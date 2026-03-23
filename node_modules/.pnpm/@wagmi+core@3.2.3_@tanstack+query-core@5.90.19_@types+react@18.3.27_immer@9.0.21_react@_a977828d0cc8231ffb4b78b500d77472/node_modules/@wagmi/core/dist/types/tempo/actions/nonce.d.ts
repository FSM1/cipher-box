import type { BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter } from '../../types/properties.js';
import type { PartialBy } from '../../types/utils.js';
import type { QueryOptions, QueryParameter } from './utils.js';
/**
 * Gets the nonce for an account and nonce key.
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
 * const nonce = await Actions.nonce.getNonce(config, {
 *   account: '0x...',
 *   nonceKey: 1n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The nonce value.
 */
export declare function getNonce<config extends Config>(config: config, parameters: getNonce.Parameters<config>): Promise<getNonce.ReturnValue>;
export declare namespace getNonce {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.nonce.getNonce.Parameters;
    type ReturnValue = Actions.nonce.getNonce.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: PartialBy<Parameters<config>, 'account' | 'nonceKey'>): readonly ["getNonce", PartialBy<Parameters<config>, "account" | "nonceKey">];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getNonce.ReturnValue> = PartialBy<getNonce.Parameters<config>, 'account' | 'nonceKey'> & QueryParameter<getNonce.ReturnValue, getNonce.ErrorType, selectData, getNonce.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getNonce.ReturnValue> = QueryOptions<getNonce.ReturnValue, getNonce.ErrorType, selectData, getNonce.QueryKey<config>>;
    }
}
/**
 * Watches for nonce incremented events.
 *
 * @deprecated This function has been deprecated post-AllegroModerato. It will be removed in a future version.
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
 * const unwatch = Actions.nonce.watchNonceIncremented(config, {
 *   onNonceIncremented: (args, log) => {
 *     console.log('Nonce incremented:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchNonceIncremented<config extends Config>(config: config, parameters: watchNonceIncremented.Parameters<config>): () => void;
export declare namespace watchNonceIncremented {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.nonce.watchNonceIncremented.Parameters;
}
//# sourceMappingURL=nonce.d.ts.map