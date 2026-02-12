import type { UseMutationResult } from '@tanstack/react-query';
import type { Config, ResolvedRegister } from '@wagmi/core';
import type { ExactPartial, UnionCompute } from '@wagmi/core/internal';
import { Actions } from '@wagmi/core/tempo';
import type { ConfigParameter } from '../../types/properties.js';
import { type UseMutationParameters, type UseQueryReturnType } from '../../utils/query.js';
import type { QueryParameter } from '../utils.js';
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
export declare function useClaim<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useClaim.Parameters<config, context>): useClaim.ReturnType<config, context>;
export declare namespace useClaim {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.reward.claim.ReturnValue, Actions.reward.claim.ErrorType, Actions.reward.claim.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.reward.claim.ReturnValue, Actions.reward.claim.ErrorType, Actions.reward.claim.Parameters<config>, context>;
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
export declare function useClaimSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useClaimSync.Parameters<config, context>): useClaimSync.ReturnType<config, context>;
export declare namespace useClaimSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.reward.claimSync.ReturnValue, Actions.reward.claimSync.ErrorType, Actions.reward.claimSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.reward.claimSync.ReturnValue, Actions.reward.claimSync.ErrorType, Actions.reward.claimSync.Parameters<config>, context>;
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
export declare function useGetGlobalRewardPerToken<config extends Config = ResolvedRegister['config'], selectData = Actions.reward.getGlobalRewardPerToken.ReturnValue>(parameters?: useGetGlobalRewardPerToken.Parameters<config, selectData>): useGetGlobalRewardPerToken.ReturnValue<selectData>;
export declare namespace useGetGlobalRewardPerToken {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.reward.getGlobalRewardPerToken.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.reward.getGlobalRewardPerToken.ReturnValue, Actions.reward.getGlobalRewardPerToken.ErrorType, selectData, Actions.reward.getGlobalRewardPerToken.QueryKey<config>> & ExactPartial<Actions.reward.getGlobalRewardPerToken.Parameters<config>>;
    type ReturnValue<selectData = Actions.reward.getGlobalRewardPerToken.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function useUserRewardInfo<config extends Config = ResolvedRegister['config'], selectData = Actions.reward.getUserRewardInfo.ReturnValue>(parameters?: useUserRewardInfo.Parameters<config, selectData>): useUserRewardInfo.ReturnValue<selectData>;
export declare namespace useUserRewardInfo {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.reward.getUserRewardInfo.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.reward.getUserRewardInfo.ReturnValue, Actions.reward.getUserRewardInfo.ErrorType, selectData, Actions.reward.getUserRewardInfo.QueryKey<config>> & ExactPartial<Actions.reward.getUserRewardInfo.Parameters<config>>;
    type ReturnValue<selectData = Actions.reward.getUserRewardInfo.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function useSetRecipient<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useSetRecipient.Parameters<config, context>): useSetRecipient.ReturnType<config, context>;
export declare namespace useSetRecipient {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.reward.setRecipient.ReturnValue, Actions.reward.setRecipient.ErrorType, Actions.reward.setRecipient.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.reward.setRecipient.ReturnValue, Actions.reward.setRecipient.ErrorType, Actions.reward.setRecipient.Parameters<config>, context>;
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
export declare function useSetRecipientSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useSetRecipientSync.Parameters<config, context>): useSetRecipientSync.ReturnType<config, context>;
export declare namespace useSetRecipientSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.reward.setRecipientSync.ReturnValue, Actions.reward.setRecipientSync.ErrorType, Actions.reward.setRecipientSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.reward.setRecipientSync.ReturnValue, Actions.reward.setRecipientSync.ErrorType, Actions.reward.setRecipientSync.Parameters<config>, context>;
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
export declare function useDistribute<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useDistribute.Parameters<config, context>): useDistribute.ReturnType<config, context>;
export declare namespace useDistribute {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.reward.distribute.ReturnValue, Actions.reward.distribute.ErrorType, Actions.reward.distribute.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.reward.distribute.ReturnValue, Actions.reward.distribute.ErrorType, Actions.reward.distribute.Parameters<config>, context>;
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
export declare function useDistributeSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useDistributeSync.Parameters<config, context>): useDistributeSync.ReturnType<config, context>;
export declare namespace useDistributeSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.reward.distributeSync.ReturnValue, Actions.reward.distributeSync.ErrorType, Actions.reward.distributeSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.reward.distributeSync.ReturnValue, Actions.reward.distributeSync.ErrorType, Actions.reward.distributeSync.Parameters<config>, context>;
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
export declare function useWatchRewardDistributed<config extends Config = ResolvedRegister['config']>(parameters?: useWatchRewardDistributed.Parameters<config>): void;
export declare namespace useWatchRewardDistributed {
    type Parameters<config extends Config = Config> = UnionCompute<ExactPartial<Actions.reward.watchRewardDistributed.Parameters<config>> & ConfigParameter<config> & {
        enabled?: boolean | undefined;
    }>;
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
export declare function useWatchRewardRecipientSet<config extends Config = ResolvedRegister['config']>(parameters?: useWatchRewardRecipientSet.Parameters<config>): void;
export declare namespace useWatchRewardRecipientSet {
    type Parameters<config extends Config = Config> = UnionCompute<ExactPartial<Actions.reward.watchRewardRecipientSet.Parameters<config>> & ConfigParameter<config> & {
        enabled?: boolean | undefined;
    }>;
}
//# sourceMappingURL=reward.d.ts.map