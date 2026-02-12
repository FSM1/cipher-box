import type { Config, ResolvedRegister } from '@wagmi/core';
import type { ExactPartial, UnionCompute } from '@wagmi/core/internal';
import { Actions } from '@wagmi/core/tempo';
import type { ConfigParameter } from '../../types/properties.js';
import { type UseQueryReturnType } from '../../utils/query.js';
import type { QueryParameter } from '../utils.js';
/**
 * Hook for getting the nonce for an account and nonce key.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.nonce.useNonce({
 *     account: '0x...',
 *     nonceKey: 1n,
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Nonce: {data?.toString()}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with nonce value.
 */
export declare function useNonce<config extends Config = ResolvedRegister['config'], selectData = Actions.nonce.getNonce.ReturnValue>(parameters?: useNonce.Parameters<config, selectData>): useNonce.ReturnValue<selectData>;
export declare namespace useNonce {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.nonce.getNonce.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.nonce.getNonce.ReturnValue, Actions.nonce.getNonce.ErrorType, selectData, Actions.nonce.getNonce.QueryKey<config>> & ExactPartial<Actions.nonce.getNonce.Parameters<config>>;
    type ReturnValue<selectData = Actions.nonce.getNonce.ReturnValue> = UseQueryReturnType<selectData, Error>;
}
/**
 * Hook for watching nonce incremented events.
 *
 * @deprecated This function has been deprecated post-AllegroModerato. It will be removed in a future version.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.nonce.useWatchNonceIncremented({
 *     onNonceIncremented(args, log) {
 *       console.log('Nonce incremented:', args)
 *     },
 *   })
 *
 *   return <div>Watching for nonce increments...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export declare function useWatchNonceIncremented<config extends Config = ResolvedRegister['config']>(parameters?: useWatchNonceIncremented.Parameters<config>): void;
export declare namespace useWatchNonceIncremented {
    type Parameters<config extends Config = Config> = UnionCompute<ExactPartial<Actions.nonce.watchNonceIncremented.Parameters<config>> & ConfigParameter<config> & {
        enabled?: boolean | undefined;
    }>;
}
//# sourceMappingURL=nonce.d.ts.map