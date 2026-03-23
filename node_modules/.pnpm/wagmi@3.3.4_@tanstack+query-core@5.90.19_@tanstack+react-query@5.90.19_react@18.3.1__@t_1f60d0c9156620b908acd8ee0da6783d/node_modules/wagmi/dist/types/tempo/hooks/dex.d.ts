import type { UseMutationResult } from '@tanstack/react-query';
import type { Config, ResolvedRegister } from '@wagmi/core';
import type { ExactPartial, UnionCompute } from '@wagmi/core/internal';
import { Actions } from '@wagmi/core/tempo';
import type { ConfigParameter } from '../../types/properties.js';
import { type UseMutationParameters, type UseQueryReturnType } from '../../utils/query.js';
import type { QueryParameter } from '../utils.js';
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
export declare function useBuy<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useBuy.Parameters<config, context>): useBuy.ReturnType<config, context>;
export declare namespace useBuy {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.buy.ReturnValue, Actions.dex.buy.ErrorType, Actions.dex.buy.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.buy.ReturnValue, Actions.dex.buy.ErrorType, Actions.dex.buy.Parameters<config>, context>;
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
export declare function useBuySync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useBuySync.Parameters<config, context>): useBuySync.ReturnType<config, context>;
export declare namespace useBuySync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.buySync.ReturnValue, Actions.dex.buySync.ErrorType, Actions.dex.buySync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.buySync.ReturnValue, Actions.dex.buySync.ErrorType, Actions.dex.buySync.Parameters<config>, context>;
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
export declare function useCancel<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useCancel.Parameters<config, context>): useCancel.ReturnType<config, context>;
export declare namespace useCancel {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.cancel.ReturnValue, Actions.dex.cancel.ErrorType, Actions.dex.cancel.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.cancel.ReturnValue, Actions.dex.cancel.ErrorType, Actions.dex.cancel.Parameters<config>, context>;
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
export declare function useCancelSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useCancelSync.Parameters<config, context>): useCancelSync.ReturnType<config, context>;
export declare namespace useCancelSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.cancelSync.ReturnValue, Actions.dex.cancelSync.ErrorType, Actions.dex.cancelSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.cancelSync.ReturnValue, Actions.dex.cancelSync.ErrorType, Actions.dex.cancelSync.Parameters<config>, context>;
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
export declare function useCancelStale<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useCancelStale.Parameters<config, context>): useCancelStale.ReturnType<config, context>;
export declare namespace useCancelStale {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.cancelStale.ReturnValue, Actions.dex.cancelStale.ErrorType, Actions.dex.cancelStale.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.cancelStale.ReturnValue, Actions.dex.cancelStale.ErrorType, Actions.dex.cancelStale.Parameters<config>, context>;
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
export declare function useCancelStaleSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useCancelStaleSync.Parameters<config, context>): useCancelStaleSync.ReturnType<config, context>;
export declare namespace useCancelStaleSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.cancelStaleSync.ReturnValue, Actions.dex.cancelStaleSync.ErrorType, Actions.dex.cancelStaleSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.cancelStaleSync.ReturnValue, Actions.dex.cancelStaleSync.ErrorType, Actions.dex.cancelStaleSync.Parameters<config>, context>;
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
export declare function useCreatePair<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useCreatePair.Parameters<config, context>): useCreatePair.ReturnType<config, context>;
export declare namespace useCreatePair {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.createPair.ReturnValue, Actions.dex.createPair.ErrorType, Actions.dex.createPair.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.createPair.ReturnValue, Actions.dex.createPair.ErrorType, Actions.dex.createPair.Parameters<config>, context>;
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
export declare function useCreatePairSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useCreatePairSync.Parameters<config, context>): useCreatePairSync.ReturnType<config, context>;
export declare namespace useCreatePairSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.createPairSync.ReturnValue, Actions.dex.createPairSync.ErrorType, Actions.dex.createPairSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.createPairSync.ReturnValue, Actions.dex.createPairSync.ErrorType, Actions.dex.createPairSync.Parameters<config>, context>;
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
export declare function useBalance<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getBalance.ReturnValue>(parameters: useBalance.Parameters<config, selectData>): useBalance.ReturnValue<selectData>;
export declare namespace useBalance {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getBalance.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.dex.getBalance.ReturnValue, Actions.dex.getBalance.ErrorType, selectData, Actions.dex.getBalance.QueryKey<config>> & ExactPartial<Actions.dex.getBalance.Parameters<config>>;
    type ReturnValue<selectData = Actions.dex.getBalance.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function useBuyQuote<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getBuyQuote.ReturnValue>(parameters: useBuyQuote.Parameters<config, selectData>): useBuyQuote.ReturnValue<selectData>;
export declare namespace useBuyQuote {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getBuyQuote.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.dex.getBuyQuote.ReturnValue, Actions.dex.getBuyQuote.ErrorType, selectData, Actions.dex.getBuyQuote.QueryKey<config>> & ExactPartial<Actions.dex.getBuyQuote.Parameters<config>>;
    type ReturnValue<selectData = Actions.dex.getBuyQuote.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function useOrder<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getOrder.ReturnValue>(parameters: useOrder.Parameters<config, selectData>): useOrder.ReturnValue<selectData>;
export declare namespace useOrder {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getOrder.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.dex.getOrder.ReturnValue, Actions.dex.getOrder.ErrorType, selectData, Actions.dex.getOrder.QueryKey<config>> & ExactPartial<Actions.dex.getOrder.Parameters<config>>;
    type ReturnValue<selectData = Actions.dex.getOrder.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function useOrderbook<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getOrderbook.ReturnValue>(parameters: useOrderbook.Parameters<config, selectData>): useOrderbook.ReturnValue<selectData>;
export declare namespace useOrderbook {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getOrderbook.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.dex.getOrderbook.ReturnValue, Actions.dex.getOrderbook.ErrorType, selectData, Actions.dex.getOrderbook.QueryKey<config>> & ExactPartial<Actions.dex.getOrderbook.Parameters<config>>;
    type ReturnValue<selectData = Actions.dex.getOrderbook.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function useTickLevel<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getTickLevel.ReturnValue>(parameters: useTickLevel.Parameters<config, selectData>): useTickLevel.ReturnValue<selectData>;
export declare namespace useTickLevel {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getTickLevel.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.dex.getTickLevel.ReturnValue, Actions.dex.getTickLevel.ErrorType, selectData, Actions.dex.getTickLevel.QueryKey<config>> & ExactPartial<Actions.dex.getTickLevel.Parameters<config>>;
    type ReturnValue<selectData = Actions.dex.getTickLevel.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function useSellQuote<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getSellQuote.ReturnValue>(parameters: useSellQuote.Parameters<config, selectData>): useSellQuote.ReturnValue<selectData>;
export declare namespace useSellQuote {
    type Parameters<config extends Config = ResolvedRegister['config'], selectData = Actions.dex.getSellQuote.ReturnValue> = ConfigParameter<config> & QueryParameter<Actions.dex.getSellQuote.ReturnValue, Actions.dex.getSellQuote.ErrorType, selectData, Actions.dex.getSellQuote.QueryKey<config>> & ExactPartial<Actions.dex.getSellQuote.Parameters<config>>;
    type ReturnValue<selectData = Actions.dex.getSellQuote.ReturnValue> = UseQueryReturnType<selectData, Error>;
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
export declare function usePlace<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: usePlace.Parameters<config, context>): usePlace.ReturnType<config, context>;
export declare namespace usePlace {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.place.ReturnValue, Actions.dex.place.ErrorType, Actions.dex.place.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.place.ReturnValue, Actions.dex.place.ErrorType, Actions.dex.place.Parameters<config>, context>;
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
export declare function usePlaceFlip<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: usePlaceFlip.Parameters<config, context>): usePlaceFlip.ReturnType<config, context>;
export declare namespace usePlaceFlip {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.placeFlip.ReturnValue, Actions.dex.placeFlip.ErrorType, Actions.dex.placeFlip.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.placeFlip.ReturnValue, Actions.dex.placeFlip.ErrorType, Actions.dex.placeFlip.Parameters<config>, context>;
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
export declare function usePlaceFlipSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: usePlaceFlipSync.Parameters<config, context>): usePlaceFlipSync.ReturnType<config, context>;
export declare namespace usePlaceFlipSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.placeFlipSync.ReturnValue, Actions.dex.placeFlipSync.ErrorType, Actions.dex.placeFlipSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.placeFlipSync.ReturnValue, Actions.dex.placeFlipSync.ErrorType, Actions.dex.placeFlipSync.Parameters<config>, context>;
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
export declare function usePlaceSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: usePlaceSync.Parameters<config, context>): usePlaceSync.ReturnType<config, context>;
export declare namespace usePlaceSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.placeSync.ReturnValue, Actions.dex.placeSync.ErrorType, Actions.dex.placeSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.placeSync.ReturnValue, Actions.dex.placeSync.ErrorType, Actions.dex.placeSync.Parameters<config>, context>;
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
export declare function useSell<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useSell.Parameters<config, context>): useSell.ReturnType<config, context>;
export declare namespace useSell {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.sell.ReturnValue, Actions.dex.sell.ErrorType, Actions.dex.sell.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.sell.ReturnValue, Actions.dex.sell.ErrorType, Actions.dex.sell.Parameters<config>, context>;
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
export declare function useSellSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useSellSync.Parameters<config, context>): useSellSync.ReturnType<config, context>;
export declare namespace useSellSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.sellSync.ReturnValue, Actions.dex.sellSync.ErrorType, Actions.dex.sellSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.sellSync.ReturnValue, Actions.dex.sellSync.ErrorType, Actions.dex.sellSync.Parameters<config>, context>;
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
export declare function useWithdraw<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useWithdraw.Parameters<config, context>): useWithdraw.ReturnType<config, context>;
export declare namespace useWithdraw {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.withdraw.ReturnValue, Actions.dex.withdraw.ErrorType, Actions.dex.withdraw.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.withdraw.ReturnValue, Actions.dex.withdraw.ErrorType, Actions.dex.withdraw.Parameters<config>, context>;
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
export declare function useWithdrawSync<config extends Config = ResolvedRegister['config'], context = unknown>(parameters?: useWithdrawSync.Parameters<config, context>): useWithdrawSync.ReturnType<config, context>;
export declare namespace useWithdrawSync {
    type Parameters<config extends Config = Config, context = unknown> = ConfigParameter<config> & {
        mutation?: UseMutationParameters<Actions.dex.withdrawSync.ReturnValue, Actions.dex.withdrawSync.ErrorType, Actions.dex.withdrawSync.Parameters<config>, context> | undefined;
    };
    type ReturnType<config extends Config = Config, context = unknown> = UseMutationResult<Actions.dex.withdrawSync.ReturnValue, Actions.dex.withdrawSync.ErrorType, Actions.dex.withdrawSync.Parameters<config>, context>;
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
export declare function useWatchFlipOrderPlaced<config extends Config = ResolvedRegister['config']>(parameters?: useWatchFlipOrderPlaced.Parameters<config>): void;
export declare namespace useWatchFlipOrderPlaced {
    type Parameters<config extends Config = Config> = UnionCompute<ExactPartial<Actions.dex.watchFlipOrderPlaced.Parameters<config>> & ConfigParameter<config> & {
        enabled?: boolean | undefined;
    }>;
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
export declare function useWatchOrderCancelled<config extends Config = ResolvedRegister['config']>(parameters?: useWatchOrderCancelled.Parameters<config>): void;
export declare namespace useWatchOrderCancelled {
    type Parameters<config extends Config = Config> = UnionCompute<ExactPartial<Actions.dex.watchOrderCancelled.Parameters<config>> & ConfigParameter<config> & {
        enabled?: boolean | undefined;
    }>;
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
export declare function useWatchOrderFilled<config extends Config = ResolvedRegister['config']>(parameters?: useWatchOrderFilled.Parameters<config>): void;
export declare namespace useWatchOrderFilled {
    type Parameters<config extends Config = Config> = UnionCompute<ExactPartial<Actions.dex.watchOrderFilled.Parameters<config>> & ConfigParameter<config> & {
        enabled?: boolean | undefined;
    }>;
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
export declare function useWatchOrderPlaced<config extends Config = ResolvedRegister['config']>(parameters?: useWatchOrderPlaced.Parameters<config>): void;
export declare namespace useWatchOrderPlaced {
    type Parameters<config extends Config = Config> = UnionCompute<ExactPartial<Actions.dex.watchOrderPlaced.Parameters<config>> & ConfigParameter<config> & {
        enabled?: boolean | undefined;
    }>;
}
//# sourceMappingURL=dex.d.ts.map