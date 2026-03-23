import { Actions } from '@wagmi/core/tempo';
import { useConfig } from '../../hooks/useConfig.js';
import { useMutation } from '../../utils/query.js';
/**
 * Hook for funding an account with an initial amount of set token(s)
 * on Tempo's testnet.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.faucet.useFund()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ account: '0xdeadbeef...' })}
 *       disabled={isPending}
 *     >
 *       Fund Account
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useFund(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.faucet.fund(config, variables);
        },
        mutationKey: ['fund'],
    });
}
/**
 * Hook for funding an account with an initial amount of set token(s)
 * on Tempo's testnet. Returns the transaction receipts.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.faucet.useFundSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ account: '0xdeadbeef...' })}
 *       disabled={isPending}
 *     >
 *       Fund Account
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useFundSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.faucet.fundSync(config, variables);
        },
        mutationKey: ['fundSync'],
    });
}
//# sourceMappingURL=faucet.js.map