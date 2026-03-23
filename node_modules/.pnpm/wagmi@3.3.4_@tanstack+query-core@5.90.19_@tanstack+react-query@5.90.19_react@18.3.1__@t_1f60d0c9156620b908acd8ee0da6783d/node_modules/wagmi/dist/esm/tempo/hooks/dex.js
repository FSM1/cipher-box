import { Actions } from '@wagmi/core/tempo';
import { useEffect } from 'react';
import { useChainId } from '../../hooks/useChainId.js';
import { useConfig } from '../../hooks/useConfig.js';
import { useMutation, useQuery, } from '../../utils/query.js';
/**
 * Hook for buying a specific amount of tokens.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useBuy()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         tokenIn: '0x20c...11',
 *         tokenOut: '0x20c...20',
 *         amountOut: parseUnits('100', 6),
 *         maxAmountIn: parseUnits('105', 6),
 *       })}
 *       disabled={isPending}
 *     >
 *       Buy Tokens
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useBuy(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.buy(config, variables);
        },
        mutationKey: ['buy'],
    });
}
/**
 * Hook for buying a specific amount of tokens.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useBuySync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         tokenIn: '0x20c...11',
 *         tokenOut: '0x20c...20',
 *         amountOut: parseUnits('100', 6),
 *         maxAmountIn: parseUnits('105', 6),
 *       })}
 *       disabled={isPending}
 *     >
 *       Buy Tokens
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useBuySync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.buySync(config, variables);
        },
        mutationKey: ['buySync'],
    });
}
/**
 * Hook for canceling an order from the orderbook.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useCancel()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ orderId: 123n })}
 *       disabled={isPending}
 *     >
 *       Cancel Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCancel(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.cancel(config, variables);
        },
        mutationKey: ['cancel'],
    });
}
/**
 * Hook for canceling an order from the orderbook.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useCancelSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ orderId: 123n })}
 *       disabled={isPending}
 *     >
 *       Cancel Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCancelSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.cancelSync(config, variables);
        },
        mutationKey: ['cancelSync'],
    });
}
/**
 * Hook for cancelling a stale order from the orderbook.
 *
 * A stale order is one where the owner's balance or allowance has dropped
 * below the order amount.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useCancelStale()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ orderId: 123n })}
 *       disabled={isPending}
 *     >
 *       Cancel Stale Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCancelStale(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.cancelStale(config, variables);
        },
        mutationKey: ['cancelStale'],
    });
}
/**
 * Hook for cancelling a stale order and waiting for confirmation.
 *
 * A stale order is one where the owner's balance or allowance has dropped
 * below the order amount.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useCancelStaleSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ orderId: 123n })}
 *       disabled={isPending}
 *     >
 *       Cancel Stale Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCancelStaleSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.cancelStaleSync(config, variables);
        },
        mutationKey: ['cancelStaleSync'],
    });
}
/**
 * Hook for creating a new trading pair on the DEX.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useCreatePair()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ base: '0x20c...11' })}
 *       disabled={isPending}
 *     >
 *       Create Pair
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCreatePair(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.createPair(config, variables);
        },
        mutationKey: ['createPair'],
    });
}
/**
 * Hook for creating a new trading pair on the DEX.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useCreatePairSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ base: '0x20c...11' })}
 *       disabled={isPending}
 *     >
 *       Create Pair
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useCreatePairSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.createPairSync(config, variables);
        },
        mutationKey: ['createPairSync'],
    });
}
/**
 * Hook for getting a user's token balance on the DEX.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.dex.useBalance({
 *     account: '0x...',
 *     token: '0x20c...11',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Balance: {data}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the user's token balance on the DEX.
 */
export function useBalance(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.dex.getBalance.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting the quote for buying a specific amount of tokens.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.dex.useBuyQuote({
 *     amountOut: parseUnits('100', 6),
 *     tokenIn: '0x20c...11',
 *     tokenOut: '0x20c...20',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Required Input: {data}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the amount of tokenIn needed.
 */
export function useBuyQuote(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.dex.getBuyQuote.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting an order's details from the orderbook.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.dex.useOrder({
 *     orderId: 123n,
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Order: {JSON.stringify(data)}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the order details.
 */
export function useOrder(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.dex.getOrder.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting orderbook information for a trading pair.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.dex.useOrderbook({
 *     base: '0x20c...11',
 *     quote: '0x20c...20',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Orderbook: {JSON.stringify(data)}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the orderbook information.
 */
export function useOrderbook(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.dex.getOrderbook.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting the tick level information at a specific tick.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 * import { Tick } from 'viem/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.dex.useTickLevel({
 *     base: '0x20c...11',
 *     tick: Tick.fromPrice('1.001'),
 *     isBid: true,
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Tick Level: {JSON.stringify(data)}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the tick level information.
 */
export function useTickLevel(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.dex.getTickLevel.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting the quote for selling a specific amount of tokens.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.dex.useSellQuote({
 *     amountIn: parseUnits('100', 6),
 *     tokenIn: '0x20c...11',
 *     tokenOut: '0x20c...20',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Expected Output: {data}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with the amount of tokenOut received.
 */
export function useSellQuote(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.dex.getSellQuote.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for placing a limit order on the orderbook.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.usePlace()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amount: parseUnits('100', 6),
 *         tick: Tick.fromPrice('0.99'),
 *         token: '0x20c...11',
 *         type: 'buy',
 *       })}
 *       disabled={isPending}
 *     >
 *       Place Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePlace(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.place(config, variables);
        },
        mutationKey: ['place'],
    });
}
/**
 * Hook for placing a flip order that automatically flips when filled.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.usePlaceFlip()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amount: parseUnits('100', 6),
 *         flipTick: Tick.fromPrice('1.01'),
 *         tick: Tick.fromPrice('0.99'),
 *         token: '0x20c...11',
 *         type: 'buy',
 *       })}
 *       disabled={isPending}
 *     >
 *       Place Flip Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePlaceFlip(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.placeFlip(config, variables);
        },
        mutationKey: ['placeFlip'],
    });
}
/**
 * Hook for placing a flip order that automatically flips when filled.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.usePlaceFlipSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amount: parseUnits('100', 6),
 *         flipTick: Tick.fromPrice('1.01'),
 *         tick: Tick.fromPrice('0.99'),
 *         token: '0x20c...11',
 *         type: 'buy',
 *       })}
 *       disabled={isPending}
 *     >
 *       Place Flip Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePlaceFlipSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.placeFlipSync(config, variables);
        },
        mutationKey: ['placeFlipSync'],
    });
}
/**
 * Hook for placing a limit order on the orderbook.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.usePlaceSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amount: parseUnits('100', 6),
 *         tick: Tick.fromPrice('0.99'),
 *         token: '0x20c...11',
 *         type: 'buy',
 *       })}
 *       disabled={isPending}
 *     >
 *       Place Order
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePlaceSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.placeSync(config, variables);
        },
        mutationKey: ['placeSync'],
    });
}
/**
 * Hook for selling a specific amount of tokens.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useSell()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amountIn: parseUnits('100', 6),
 *         minAmountOut: parseUnits('95', 6),
 *         tokenIn: '0x20c...11',
 *         tokenOut: '0x20c...20',
 *       })}
 *       disabled={isPending}
 *     >
 *       Sell Tokens
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSell(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.sell(config, variables);
        },
        mutationKey: ['sell'],
    });
}
/**
 * Hook for selling a specific amount of tokens.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useSellSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amountIn: parseUnits('100', 6),
 *         minAmountOut: parseUnits('95', 6),
 *         tokenIn: '0x20c...11',
 *         tokenOut: '0x20c...20',
 *       })}
 *       disabled={isPending}
 *     >
 *       Sell Tokens
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSellSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.sellSync(config, variables);
        },
        mutationKey: ['sellSync'],
    });
}
/**
 * Hook for withdrawing tokens from the DEX to the caller's wallet.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useWithdraw()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amount: 100n,
 *         token: '0x20c...11',
 *       })}
 *       disabled={isPending}
 *     >
 *       Withdraw
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useWithdraw(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.withdraw(config, variables);
        },
        mutationKey: ['withdraw'],
    });
}
/**
 * Hook for withdrawing tokens from the DEX to the caller's wallet.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.dex.useWithdrawSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({
 *         amount: 100n,
 *         token: '0x20c...11',
 *       })}
 *       disabled={isPending}
 *     >
 *       Withdraw
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useWithdrawSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.dex.withdrawSync(config, variables);
        },
        mutationKey: ['withdrawSync'],
    });
}
/**
 * Hook for watching flip order placement events on the DEX.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.dex.useWatchFlipOrderPlaced({
 *     onFlipOrderPlaced(args) {
 *       console.log('Flip order placed:', args)
 *     },
 *   })
 *
 *   return <div>Watching for flip order placements...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchFlipOrderPlaced(parameters = {}) {
    const { enabled = true, onFlipOrderPlaced, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onFlipOrderPlaced)
            return;
        return Actions.dex.watchFlipOrderPlaced(config, {
            ...rest,
            chainId,
            onFlipOrderPlaced,
        });
    }, [
        config,
        enabled,
        chainId,
        onFlipOrderPlaced,
        rest.fromBlock,
        rest.maker,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
        rest.token,
    ]);
}
/**
 * Hook for watching order cancellation events on the DEX.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.dex.useWatchOrderCancelled({
 *     onOrderCancelled(args) {
 *       console.log('Order cancelled:', args)
 *     },
 *   })
 *
 *   return <div>Watching for order cancellations...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchOrderCancelled(parameters = {}) {
    const { enabled = true, onOrderCancelled, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onOrderCancelled)
            return;
        return Actions.dex.watchOrderCancelled(config, {
            ...rest,
            chainId,
            onOrderCancelled,
        });
    }, [
        config,
        enabled,
        chainId,
        onOrderCancelled,
        rest.fromBlock,
        rest.onError,
        rest.orderId,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching order filled events on the DEX.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.dex.useWatchOrderFilled({
 *     onOrderFilled(args) {
 *       console.log('Order filled:', args)
 *     },
 *   })
 *
 *   return <div>Watching for order fills...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchOrderFilled(parameters = {}) {
    const { enabled = true, onOrderFilled, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onOrderFilled)
            return;
        return Actions.dex.watchOrderFilled(config, {
            ...rest,
            chainId,
            onOrderFilled,
        });
    }, [
        config,
        enabled,
        chainId,
        onOrderFilled,
        rest.fromBlock,
        rest.maker,
        rest.onError,
        rest.orderId,
        rest.poll,
        rest.pollingInterval,
        rest.taker,
    ]);
}
/**
 * Hook for watching order placement events on the DEX.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.dex.useWatchOrderPlaced({
 *     onOrderPlaced(args) {
 *       console.log('Order placed:', args)
 *     },
 *   })
 *
 *   return <div>Watching for order placements...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchOrderPlaced(parameters = {}) {
    const { enabled = true, onOrderPlaced, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onOrderPlaced)
            return;
        return Actions.dex.watchOrderPlaced(config, {
            ...rest,
            chainId,
            onOrderPlaced,
        });
    }, [
        config,
        enabled,
        chainId,
        onOrderPlaced,
        rest.fromBlock,
        rest.maker,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
        rest.token,
    ]);
}
//# sourceMappingURL=dex.js.map