import { Actions } from '@wagmi/core/tempo';
import { useEffect } from 'react';
import { useChainId } from '../../hooks/useChainId.js';
import { useConfig } from '../../hooks/useConfig.js';
import { useMutation, useQuery, } from '../../utils/query.js';
/**
 * Hook for claiming accumulated rewards.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate: claim } = Hooks.reward.useClaim()
 *
 *   return (
 *     <button onClick={() => claim({
 *       token: '0x20c0000000000000000000000000000000000001'
 *     })}>
 *       Claim Rewards
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useClaim(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.reward.claim(config, variables);
        },
        mutationKey: ['claim'],
    });
}
/**
 * Hook for claiming accumulated rewards and waiting for confirmation.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate: claimSync } = Hooks.reward.useClaimSync()
 *
 *   return (
 *     <button onClick={() => claimSync({
 *       token: '0x20c0000000000000000000000000000000000001'
 *     })}>
 *       Claim Rewards
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useClaimSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.reward.claimSync(config, variables);
        },
        mutationKey: ['claimSync'],
    });
}
/**
 * Hook for getting the global reward per token value.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.reward.useGetGlobalRewardPerToken({
 *     token: '0x20c0000000000000000000000000000000000001',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Value: {data?.toString()}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with global reward per token value.
 */
export function useGetGlobalRewardPerToken(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.reward.getGlobalRewardPerToken.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting the reward information for a specific account.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.reward.useUserRewardInfo({
 *     token: '0x20c0000000000000000000000000000000000001',
 *     account: '0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return (
 *     <div>
 *       <div>Recipient: {data?.rewardRecipient}</div>
 *       <div>Reward per token: {data?.rewardPerToken.toString()}</div>
 *       <div>Reward balance: {data?.rewardBalance.toString()}</div>
 *     </div>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with reward information (recipient, rewardPerToken, rewardBalance).
 */
export function useUserRewardInfo(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.reward.getUserRewardInfo.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for setting the reward recipient for a token holder.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate: setRecipient } = Hooks.reward.useSetRecipient()
 *
 *   return (
 *     <button onClick={() => setRecipient({
 *       recipient: '0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC',
 *       token: '0x20c0000000000000000000000000000000000001',
 *     })}>
 *       Set Recipient
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetRecipient(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.reward.setRecipient(config, variables);
        },
        mutationKey: ['setRecipient'],
    });
}
/**
 * Hook for setting the reward recipient and waiting for confirmation.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate: setRecipientSync } = Hooks.reward.useSetRecipientSync()
 *
 *   return (
 *     <button onClick={() => setRecipientSync({
 *       recipient: '0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC',
 *       token: '0x20c0000000000000000000000000000000000001',
 *     })}>
 *       Set Recipient
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetRecipientSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.reward.setRecipientSync(config, variables);
        },
        mutationKey: ['setRecipientSync'],
    });
}
/**
 * Hook for distributing rewards.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate: distribute } = Hooks.reward.useDistribute()
 *
 *   return (
 *     <button onClick={() => distribute({
 *       amount: 100000000000000000000n,
 *       seconds: 86400,
 *       token: '0x20c0000000000000000000000000000000000001',
 *     })}>
 *       Start Reward
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useDistribute(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.reward.distribute(config, variables);
        },
        mutationKey: ['distribute'],
    });
}
/**
 * Hook for distributing rewards and waiting for confirmation.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate: distributeSync } = Hooks.reward.useDistributeSync()
 *
 *   return (
 *     <button onClick={() => distributeSync({
 *       amount: 100000000000000000000n,
 *       seconds: 86400,
 *       token: '0x20c0000000000000000000000000000000000001',
 *     })}>
 *       Start Reward
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useDistributeSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.reward.distributeSync(config, variables);
        },
        mutationKey: ['distributeSync'],
    });
}
/**
 * Hook for watching reward distributed events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.reward.useWatchRewardDistributed({
 *     token: '0x20c0000000000000000000000000000000000001',
 *     onRewardDistributed(args) {
 *       console.log('Reward distributed:', args)
 *     },
 *   })
 *
 *   return <div>Watching for reward distributed events...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchRewardDistributed(parameters = {}) {
    const { enabled = true, onRewardDistributed, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onRewardDistributed)
            return;
        if (!token)
            return;
        return Actions.reward.watchRewardDistributed(config, {
            ...rest,
            chainId,
            onRewardDistributed,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onRewardDistributed,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching reward recipient set events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.reward.useWatchRewardRecipientSet({
 *     token: '0x20c0000000000000000000000000000000000001',
 *     onRewardRecipientSet(args) {
 *       console.log('Reward recipient set:', args)
 *     },
 *   })
 *
 *   return <div>Watching for reward recipient set events...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchRewardRecipientSet(parameters = {}) {
    const { enabled = true, onRewardRecipientSet, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onRewardRecipientSet)
            return;
        if (!token)
            return;
        return Actions.reward.watchRewardRecipientSet(config, {
            ...rest,
            chainId,
            onRewardRecipientSet,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onRewardRecipientSet,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
//# sourceMappingURL=reward.js.map