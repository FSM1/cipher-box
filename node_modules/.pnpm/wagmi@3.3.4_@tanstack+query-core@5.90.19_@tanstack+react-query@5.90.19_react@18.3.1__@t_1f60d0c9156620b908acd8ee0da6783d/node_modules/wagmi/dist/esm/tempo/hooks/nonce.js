import { Actions } from '@wagmi/core/tempo';
import { useEffect } from 'react';
import { useChainId } from '../../hooks/useChainId.js';
import { useConfig } from '../../hooks/useConfig.js';
import { useQuery } from '../../utils/query.js';
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
export function useNonce(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.nonce.getNonce.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
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
export function useWatchNonceIncremented(parameters = {}) {
    const { enabled = true, onNonceIncremented, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onNonceIncremented)
            return;
        return Actions.nonce.watchNonceIncremented(config, {
            ...rest,
            chainId,
            onNonceIncremented,
        });
    }, [
        config,
        enabled,
        chainId,
        onNonceIncremented,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
//# sourceMappingURL=nonce.js.map