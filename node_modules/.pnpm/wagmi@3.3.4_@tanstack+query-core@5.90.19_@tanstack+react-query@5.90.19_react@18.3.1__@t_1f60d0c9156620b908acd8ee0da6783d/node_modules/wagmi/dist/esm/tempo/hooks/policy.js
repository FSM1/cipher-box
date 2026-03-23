import { Actions } from '@wagmi/core/tempo';
import { useEffect } from 'react';
import { useChainId } from '../../hooks/useChainId.js';
import { useConfig } from '../../hooks/useConfig.js';
import { useMutation, useQuery, } from '../../utils/query.js';
/**
 * Hook for creating a new policy.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useCreate()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ type: 'whitelist' })}
 *       disabled={isPending}
 *     >
 *       Create Policy
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCreate(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.create(config, variables);
        },
        mutationKey: ['create'],
    });
}
/**
 * Hook for creating a new policy.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useCreateSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ type: 'whitelist' })}
 *       disabled={isPending}
 *     >
 *       Create Policy
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCreateSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.createSync(config, variables);
        },
        mutationKey: ['createSync'],
    });
}
/**
 * Hook for setting the admin for a policy.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useSetAdmin()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ policyId: 2n, admin: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Set Admin
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetAdmin(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.setAdmin(config, variables);
        },
        mutationKey: ['setAdmin'],
    });
}
/**
 * Hook for setting the admin for a policy.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useSetAdminSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ policyId: 2n, admin: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Set Admin
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetAdminSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.setAdminSync(config, variables);
        },
        mutationKey: ['setAdminSync'],
    });
}
/**
 * Hook for modifying a policy whitelist.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useModifyWhitelist()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ policyId: 2n, address: '0x...', allowed: true })}
 *       disabled={isPending}
 *     >
 *       Add to Whitelist
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useModifyWhitelist(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.modifyWhitelist(config, variables);
        },
        mutationKey: ['modifyWhitelist'],
    });
}
/**
 * Hook for modifying a policy whitelist.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useModifyWhitelistSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ policyId: 2n, address: '0x...', allowed: true })}
 *       disabled={isPending}
 *     >
 *       Add to Whitelist
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useModifyWhitelistSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.modifyWhitelistSync(config, variables);
        },
        mutationKey: ['modifyWhitelistSync'],
    });
}
/**
 * Hook for modifying a policy blacklist.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useModifyBlacklist()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ policyId: 2n, address: '0x...', restricted: true })}
 *       disabled={isPending}
 *     >
 *       Add to Blacklist
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useModifyBlacklist(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.modifyBlacklist(config, variables);
        },
        mutationKey: ['modifyBlacklist'],
    });
}
/**
 * Hook for modifying a policy blacklist.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.policy.useModifyBlacklistSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ policyId: 2n, address: '0x...', restricted: true })}
 *       disabled={isPending}
 *     >
 *       Add to Blacklist
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useModifyBlacklistSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.policy.modifyBlacklistSync(config, variables);
        },
        mutationKey: ['modifyBlacklistSync'],
    });
}
/**
 * Hook for getting policy data.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.policy.useData({
 *     policyId: 2n,
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Admin: {data?.admin}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with policy data.
 */
export function useData(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.policy.getData.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for checking if a user is authorized by a policy.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.policy.useIsAuthorized({
 *     policyId: 2n,
 *     user: '0x...',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Authorized: {data ? 'Yes' : 'No'}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with authorization status.
 */
export function useIsAuthorized(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.policy.isAuthorized.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for watching policy creation events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.policy.useWatchCreate({
 *     onPolicyCreated(args) {
 *       console.log('Policy created:', args)
 *     },
 *   })
 *
 *   return <div>Watching for policy creation...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchCreate(parameters = {}) {
    const { enabled = true, onPolicyCreated, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onPolicyCreated)
            return;
        return Actions.policy.watchCreate(config, {
            ...rest,
            chainId,
            onPolicyCreated,
        });
    }, [
        config,
        enabled,
        chainId,
        onPolicyCreated,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching policy admin update events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.policy.useWatchAdminUpdated({
 *     onAdminUpdated(args) {
 *       console.log('Policy admin updated:', args)
 *     },
 *   })
 *
 *   return <div>Watching for admin updates...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchAdminUpdated(parameters = {}) {
    const { enabled = true, onAdminUpdated, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onAdminUpdated)
            return;
        return Actions.policy.watchAdminUpdated(config, {
            ...rest,
            chainId,
            onAdminUpdated,
        });
    }, [
        config,
        enabled,
        chainId,
        onAdminUpdated,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching whitelist update events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.policy.useWatchWhitelistUpdated({
 *     onWhitelistUpdated(args) {
 *       console.log('Whitelist updated:', args)
 *     },
 *   })
 *
 *   return <div>Watching for whitelist updates...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchWhitelistUpdated(parameters = {}) {
    const { enabled = true, onWhitelistUpdated, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onWhitelistUpdated)
            return;
        return Actions.policy.watchWhitelistUpdated(config, {
            ...rest,
            chainId,
            onWhitelistUpdated,
        });
    }, [
        config,
        enabled,
        chainId,
        onWhitelistUpdated,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching blacklist update events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.policy.useWatchBlacklistUpdated({
 *     onBlacklistUpdated(args) {
 *       console.log('Blacklist updated:', args)
 *     },
 *   })
 *
 *   return <div>Watching for blacklist updates...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchBlacklistUpdated(parameters = {}) {
    const { enabled = true, onBlacklistUpdated, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onBlacklistUpdated)
            return;
        return Actions.policy.watchBlacklistUpdated(config, {
            ...rest,
            chainId,
            onBlacklistUpdated,
        });
    }, [
        config,
        enabled,
        chainId,
        onBlacklistUpdated,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
//# sourceMappingURL=policy.js.map