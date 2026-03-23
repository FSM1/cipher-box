import { Actions } from '@wagmi/core/tempo';
import { useEffect } from 'react';
import { useChainId } from '../../hooks/useChainId.js';
import { useConfig } from '../../hooks/useConfig.js';
import { useMutation, useQuery, } from '../../utils/query.js';
/**
 * Hook for getting the user's default fee token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.fee.useUserToken({
 *     account: '0x20c...0055',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Token: {data?.address}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with token address and ID.
 */
export function useUserToken(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.fee.getUserToken.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for setting the user's default fee token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.fee.useSetUserToken()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x20c...0055' })}
 *       disabled={isPending}
 *     >
 *       Set Token
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetUserToken(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.fee.setUserToken(config, variables);
        },
        mutationKey: ['setUserToken'],
    });
}
/**
 * Hook for setting the user's default fee token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.fee.useSetUserTokenSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x20c...0055' })}
 *       disabled={isPending}
 *     >
 *       Set Token
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetUserTokenSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.fee.setUserTokenSync(config, variables);
        },
        mutationKey: ['setUserTokenSync'],
    });
}
/**
 * Hook for watching user token set events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.fee.useWatchSetUserToken({
 *     onUserTokenSet(args) {
 *       console.log('User token set:', args)
 *     },
 *   })
 *
 *   return <div>Watching for user token changes...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchSetUserToken(parameters = {}) {
    const { enabled = true, onUserTokenSet, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onUserTokenSet)
            return;
        return Actions.fee.watchSetUserToken(config, {
            ...rest,
            chainId,
            onUserTokenSet,
        });
    }, [
        config,
        enabled,
        chainId,
        onUserTokenSet,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
//# sourceMappingURL=fee.js.map