import { Actions } from '@wagmi/core/tempo';
import { useEffect } from 'react';
import { useChainId } from '../../hooks/useChainId.js';
import { useConfig } from '../../hooks/useConfig.js';
import { useMutation, useQuery, } from '../../utils/query.js';
/**
 * Hook for getting the reserves for a liquidity pool.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.amm.usePool({
 *     userToken: '0x...',
 *     validatorToken: '0x...',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return (
 *     <div>
 *       User Token Reserve: {data?.reserveUserToken.toString()}
 *       Validator Token Reserve: {data?.reserveValidatorToken.toString()}
 *     </div>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the pool reserves.
 */
export function usePool(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.amm.getPool.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting the LP token balance for an account in a specific pool.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data: poolId } = Hooks.amm.usePoolId({
 *     userToken: '0x...',
 *     validatorToken: '0x...',
 *   })
 *
 *   const { data, isLoading } = Hooks.amm.useLiquidityBalance({
 *     poolId,
 *     address: '0x20c...0055',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>LP Balance: {data?.toString()}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the LP token balance.
 */
export function useLiquidityBalance(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.amm.getLiquidityBalance.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for performing a rebalance swap from validator token to user token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.amm.useRebalanceSwap()
 *
 *   return (
 *     <button
 *       onClick={() =>
 *         mutate({
 *           userToken: '0x...',
 *           validatorToken: '0x...',
 *           amountOut: 100n,
 *           to: '0x...',
 *         })
 *       }
 *       disabled={isPending}
 *     >
 *       Rebalance Swap
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useRebalanceSwap(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.amm.rebalanceSwap(config, variables);
        },
        mutationKey: ['rebalanceSwap'],
    });
}
/**
 * Hook for performing a rebalance swap from validator token to user token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.amm.useRebalanceSwapSync()
 *
 *   return (
 *     <button
 *       onClick={() =>
 *         mutate({
 *           userToken: '0x...',
 *           validatorToken: '0x...',
 *           amountOut: 100n,
 *           to: '0x...',
 *         })
 *       }
 *       disabled={isPending}
 *     >
 *       Rebalance Swap
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useRebalanceSwapSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.amm.rebalanceSwapSync(config, variables);
        },
        mutationKey: ['rebalanceSwapSync'],
    });
}
/**
 * Hook for adding liquidity to a pool.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.amm.useMint()
 *
 *   return (
 *     <button
 *       onClick={() =>
 *         mutate({
 *           userTokenAddress: '0x20c0...beef',
 *           validatorTokenAddress: '0x20c0...babe',
 *           validatorTokenAmount: 100n,
 *           to: '0xfeed...fede',
 *         })
 *       }
 *       disabled={isPending}
 *     >
 *       Add Liquidity
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useMint(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.amm.mint(config, variables);
        },
        mutationKey: ['mint'],
    });
}
/**
 * Hook for adding liquidity to a pool.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.amm.useMintSync()
 *
 *   return (
 *     <button
 *       onClick={() =>
 *         mutate({
 *           userTokenAddress: '0x20c0...beef',
 *           validatorTokenAddress: '0x20c0...babe',
 *           validatorTokenAmount: 100n,
 *           to: '0xfeed...fede',
 *         })
 *       }
 *       disabled={isPending}
 *     >
 *       Add Liquidity
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useMintSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.amm.mintSync(config, variables);
        },
        mutationKey: ['mintSync'],
    });
}
/**
 * Hook for removing liquidity from a pool.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.amm.useBurn()
 *
 *   return (
 *     <button
 *       onClick={() =>
 *         mutate({
 *           userToken: '0x20c0...beef',
 *           validatorToken: '0x20c0...babe',
 *           liquidity: 50n,
 *           to: '0xfeed...fede',
 *         })
 *       }
 *       disabled={isPending}
 *     >
 *       Remove Liquidity
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useBurn(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.amm.burn(config, variables);
        },
        mutationKey: ['burn'],
    });
}
/**
 * Hook for removing liquidity from a pool.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.amm.useBurnSync()
 *
 *   return (
 *     <button
 *       onClick={() =>
 *         mutate({
 *           userToken: '0x20c0...beef',
 *           validatorToken: '0x20c0...babe',
 *           liquidity: 50n,
 *           to: '0xfeed...fede',
 *         })
 *       }
 *       disabled={isPending}
 *     >
 *       Remove Liquidity
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useBurnSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.amm.burnSync(config, variables);
        },
        mutationKey: ['burnSync'],
    });
}
/**
 * Hook for watching rebalance swap events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.amm.useWatchRebalanceSwap({
 *     onRebalanceSwap(args) {
 *       console.log('Rebalance swap:', args)
 *     },
 *   })
 *
 *   return <div>Watching for rebalance swaps...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchRebalanceSwap(parameters = {}) {
    const { enabled = true, onRebalanceSwap, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onRebalanceSwap)
            return;
        return Actions.amm.watchRebalanceSwap(config, {
            ...rest,
            chainId,
            onRebalanceSwap,
        });
    }, [
        config,
        enabled,
        chainId,
        onRebalanceSwap,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
        rest.userToken,
        rest.validatorToken,
    ]);
}
/**
 * Hook for watching liquidity mint events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.amm.useWatchMint({
 *     onMint(args) {
 *       console.log('Liquidity added:', args)
 *     },
 *   })
 *
 *   return <div>Watching for liquidity additions...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchMint(parameters = {}) {
    const { enabled = true, onMint, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onMint)
            return;
        return Actions.amm.watchMint(config, {
            ...rest,
            chainId,
            onMint,
        });
    }, [
        config,
        enabled,
        chainId,
        onMint,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
        rest.sender,
        rest.userToken,
        rest.validatorToken,
    ]);
}
/**
 * Hook for watching liquidity burn events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.amm.useWatchBurn({
 *     onBurn(args) {
 *       console.log('Liquidity removed:', args)
 *     },
 *   })
 *
 *   return <div>Watching for liquidity removals...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchBurn(parameters = {}) {
    const { enabled = true, onBurn, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onBurn)
            return;
        return Actions.amm.watchBurn(config, {
            ...rest,
            chainId,
            onBurn,
        });
    }, [
        config,
        enabled,
        chainId,
        onBurn,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
        rest.userToken,
        rest.validatorToken,
    ]);
}
//# sourceMappingURL=amm.js.map