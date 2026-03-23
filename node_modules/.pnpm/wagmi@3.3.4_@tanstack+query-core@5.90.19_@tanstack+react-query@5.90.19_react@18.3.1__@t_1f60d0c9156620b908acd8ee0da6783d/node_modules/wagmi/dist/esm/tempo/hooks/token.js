import { Actions } from '@wagmi/core/tempo';
import { useEffect } from 'react';
import { useChainId } from '../../hooks/useChainId.js';
import { useConfig } from '../../hooks/useConfig.js';
import { useMutation, useQuery, } from '../../utils/query.js';
/**
 * Hook for approving a spender to transfer TIP20 tokens.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useApprove()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ spender: '0x...', amount: 100n })}
 *       disabled={isPending}
 *     >
 *       Approve
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useApprove(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.approve(config, variables);
        },
        mutationKey: ['approve'],
    });
}
/**
 * Hook for approving a spender to transfer TIP20 tokens.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useApproveSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ spender: '0x...', amount: 100n })}
 *       disabled={isPending}
 *     >
 *       Approve
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useApproveSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.approveSync(config, variables);
        },
        mutationKey: ['approveSync'],
    });
}
/**
 * Hook for burning TIP20 tokens from the caller's balance.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useBurn()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ amount: 100n, token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Burn
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
            return Actions.token.burn(config, variables);
        },
        mutationKey: ['burn'],
    });
}
/**
 * Hook for burning TIP20 tokens from the caller's balance.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useBurnSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ amount: 100n, token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Burn
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
            return Actions.token.burnSync(config, variables);
        },
        mutationKey: ['burnSync'],
    });
}
/**
 * Hook for burning TIP20 tokens from a blocked address.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useBurnBlocked()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ from: '0x...', amount: 100n, token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Burn Blocked
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useBurnBlocked(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.burnBlocked(config, variables);
        },
        mutationKey: ['burnBlocked'],
    });
}
/**
 * Hook for burning TIP20 tokens from a blocked address.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useBurnBlockedSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ from: '0x...', amount: 100n, token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Burn Blocked
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useBurnBlockedSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.burnBlockedSync(config, variables);
        },
        mutationKey: ['burnBlockedSync'],
    });
}
/**
 * Hook for changing the transfer policy ID for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useChangeTransferPolicy()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', policyId: 1n })}
 *       disabled={isPending}
 *     >
 *       Change Policy
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useChangeTransferPolicy(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.changeTransferPolicy(config, variables);
        },
        mutationKey: ['changeTransferPolicy'],
    });
}
/**
 * Hook for changing the transfer policy ID for a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useChangeTransferPolicySync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', policyId: 1n })}
 *       disabled={isPending}
 *     >
 *       Change Policy
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useChangeTransferPolicySync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.changeTransferPolicySync(config, variables);
        },
        mutationKey: ['changeTransferPolicySync'],
    });
}
/**
 * Hook for creating a new TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useCreate()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ name: 'My Token', symbol: 'MTK', currency: 'USD' })}
 *       disabled={isPending}
 *     >
 *       Create Token
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
            return Actions.token.create(config, variables);
        },
        mutationKey: ['create'],
    });
}
/**
 * Hook for creating a new TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useCreateSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ name: 'My Token', symbol: 'MTK', currency: 'USD' })}
 *       disabled={isPending}
 *     >
 *       Create Token
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
            return Actions.token.createSync(config, variables);
        },
        mutationKey: ['createSync'],
    });
}
/**
 * Hook for updating the quote token for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useUpdateQuoteToken()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Update Quote Token
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useUpdateQuoteToken(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.updateQuoteToken(config, variables);
        },
        mutationKey: ['updateQuoteToken'],
    });
}
/**
 * Hook for updating the quote token for a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useUpdateQuoteTokenSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Update Quote Token
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useUpdateQuoteTokenSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.updateQuoteTokenSync(config, variables);
        },
        mutationKey: ['updateQuoteTokenSync'],
    });
}
/**
 * Hook for getting TIP20 token allowance.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.token.useGetAllowance({
 *     account: '0x...',
 *     spender: '0x...',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Allowance: {data?.toString()}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with token allowance.
 */
export function useGetAllowance(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.token.getAllowance.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting TIP20 token balance for an address.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.token.useGetBalance({
 *     account: '0x...',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Balance: {data?.toString()}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with token balance.
 */
export function useGetBalance(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.token.getBalance.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting TIP20 token metadata.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.token.useGetMetadata({
 *     token: '0x...',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>{data?.name} ({data?.symbol})</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with token metadata.
 */
export function useGetMetadata(parameters = {}) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.token.getMetadata.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for getting the admin role for a specific role in a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.token.useGetRoleAdmin({
 *     role: 'issuer',
 *     token: '0x...',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Admin Role: {data}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with admin role hash.
 */
export function useGetRoleAdmin(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.token.getRoleAdmin.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for granting roles for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useGrantRoles()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', to: '0x...', roles: ['issuer'] })}
 *       disabled={isPending}
 *     >
 *       Grant Roles
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useGrantRoles(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.grantRoles(config, variables);
        },
        mutationKey: ['grantRoles'],
    });
}
/**
 * Hook for granting roles for a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useGrantRolesSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', to: '0x...', roles: ['issuer'] })}
 *       disabled={isPending}
 *     >
 *       Grant Roles
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useGrantRolesSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.grantRolesSync(config, variables);
        },
        mutationKey: ['grantRolesSync'],
    });
}
/**
 * Hook for checking if an account has a specific role for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { data, isLoading } = Hooks.token.useHasRole({
 *     account: '0x...',
 *     role: 'issuer',
 *     token: '0x...',
 *   })
 *
 *   if (isLoading) return <div>Loading...</div>
 *   return <div>Has Role: {data ? 'Yes' : 'No'}</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Query result with boolean indicating if account has role.
 */
export function useHasRole(parameters) {
    const config = useConfig(parameters);
    const chainId = useChainId({ config });
    const options = Actions.token.hasRole.queryOptions(config, {
        ...parameters,
        chainId: parameters.chainId ?? chainId,
    });
    return useQuery(options);
}
/**
 * Hook for minting TIP20 tokens to an address.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useMint()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ to: '0x...', amount: 100n, token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Mint
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
            return Actions.token.mint(config, variables);
        },
        mutationKey: ['mint'],
    });
}
/**
 * Hook for minting TIP20 tokens to an address.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useMintSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ to: '0x...', amount: 100n, token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Mint
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
            return Actions.token.mintSync(config, variables);
        },
        mutationKey: ['mintSync'],
    });
}
/**
 * Hook for pausing a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.usePause()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Pause
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePause(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.pause(config, variables);
        },
        mutationKey: ['pause'],
    });
}
/**
 * Hook for pausing a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.usePauseSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Pause
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePauseSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.pauseSync(config, variables);
        },
        mutationKey: ['pauseSync'],
    });
}
/**
 * Hook for renouncing roles for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useRenounceRoles()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', roles: ['issuer'] })}
 *       disabled={isPending}
 *     >
 *       Renounce Roles
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useRenounceRoles(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.renounceRoles(config, variables);
        },
        mutationKey: ['renounceRoles'],
    });
}
/**
 * Hook for renouncing roles for a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useRenounceRolesSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', roles: ['issuer'] })}
 *       disabled={isPending}
 *     >
 *       Renounce Roles
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useRenounceRolesSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.renounceRolesSync(config, variables);
        },
        mutationKey: ['renounceRolesSync'],
    });
}
/**
 * Hook for revoking roles for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useRevokeRoles()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', from: '0x...', roles: ['issuer'] })}
 *       disabled={isPending}
 *     >
 *       Revoke Roles
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useRevokeRoles(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.revokeRoles(config, variables);
        },
        mutationKey: ['revokeRoles'],
    });
}
/**
 * Hook for revoking roles for a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useRevokeRolesSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', from: '0x...', roles: ['issuer'] })}
 *       disabled={isPending}
 *     >
 *       Revoke Roles
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useRevokeRolesSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.revokeRolesSync(config, variables);
        },
        mutationKey: ['revokeRolesSync'],
    });
}
/**
 * Hook for setting the admin role for a specific role in a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useSetRoleAdmin()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', role: 'issuer', adminRole: 'pause' })}
 *       disabled={isPending}
 *     >
 *       Set Role Admin
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetRoleAdmin(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.setRoleAdmin(config, variables);
        },
        mutationKey: ['setRoleAdmin'],
    });
}
/**
 * Hook for setting the admin role for a specific role in a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useSetRoleAdminSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', role: 'issuer', adminRole: 'pause' })}
 *       disabled={isPending}
 *     >
 *       Set Role Admin
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetRoleAdminSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.setRoleAdminSync(config, variables);
        },
        mutationKey: ['setRoleAdminSync'],
    });
}
/**
 * Hook for setting the supply cap for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useSetSupplyCap()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', supplyCap: 1000000n })}
 *       disabled={isPending}
 *     >
 *       Set Supply Cap
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetSupplyCap(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.setSupplyCap(config, variables);
        },
        mutationKey: ['setSupplyCap'],
    });
}
/**
 * Hook for setting the supply cap for a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useSetSupplyCapSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', supplyCap: 1000000n })}
 *       disabled={isPending}
 *     >
 *       Set Supply Cap
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useSetSupplyCapSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.setSupplyCapSync(config, variables);
        },
        mutationKey: ['setSupplyCapSync'],
    });
}
/**
 * Hook for transferring TIP20 tokens to another address.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useTransfer()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ to: '0x...', amount: 100n })}
 *       disabled={isPending}
 *     >
 *       Transfer
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useTransfer(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.transfer(config, variables);
        },
        mutationKey: ['transfer'],
    });
}
/**
 * Hook for transferring TIP20 tokens to another address.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useTransferSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ to: '0x...', amount: 100n })}
 *       disabled={isPending}
 *     >
 *       Transfer
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useTransferSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.transferSync(config, variables);
        },
        mutationKey: ['transferSync'],
    });
}
/**
 * Hook for unpausing a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useUnpause()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Unpause
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useUnpause(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.unpause(config, variables);
        },
        mutationKey: ['unpause'],
    });
}
/**
 * Hook for unpausing a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.useUnpauseSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Unpause
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function useUnpauseSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.unpauseSync(config, variables);
        },
        mutationKey: ['unpauseSync'],
    });
}
/**
 * Hook for preparing the quote token update for a TIP20 token.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.usePrepareUpdateQuoteToken()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', quoteToken: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Prepare Update Quote Token
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePrepareUpdateQuoteToken(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.prepareUpdateQuoteToken(config, variables);
        },
        mutationKey: ['prepareUpdateQuoteToken'],
    });
}
/**
 * Hook for preparing the quote token update for a TIP20 token.
 *
 * Note: This is a synchronous hook that waits for the transaction
 * to be included on a block before returning a response.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   const { mutate, isPending } = Hooks.token.usePrepareUpdateQuoteTokenSync()
 *
 *   return (
 *     <button
 *       onClick={() => mutate({ token: '0x...', quoteToken: '0x...' })}
 *       disabled={isPending}
 *     >
 *       Prepare Update Quote Token
 *     </button>
 *   )
 * }
 * ```
 *
 * @param parameters - Parameters.
 * @returns Mutation result.
 */
export function usePrepareUpdateQuoteTokenSync(parameters = {}) {
    const { mutation } = parameters;
    const config = useConfig(parameters);
    return useMutation({
        ...mutation,
        async mutationFn(variables) {
            return Actions.token.prepareUpdateQuoteTokenSync(config, variables);
        },
        mutationKey: ['prepareUpdateQuoteTokenSync'],
    });
}
/**
 * Hook for watching TIP20 token role admin updates.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchAdminRole({
 *     onRoleAdminUpdated(args) {
 *       console.log('Role admin updated:', args)
 *     },
 *   })
 *
 *   return <div>Watching for role admin updates...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchAdminRole(parameters = {}) {
    const { enabled = true, onRoleAdminUpdated, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onRoleAdminUpdated)
            return;
        if (!token)
            return;
        return Actions.token.watchAdminRole(config, {
            ...rest,
            chainId,
            onRoleAdminUpdated,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onRoleAdminUpdated,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching TIP20 token approval events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchApprove({
 *     onApproval(args) {
 *       console.log('Approval:', args)
 *     },
 *   })
 *
 *   return <div>Watching for approvals...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchApprove(parameters = {}) {
    const { enabled = true, onApproval, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onApproval)
            return;
        if (!token)
            return;
        return Actions.token.watchApprove(config, {
            ...rest,
            chainId,
            onApproval,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onApproval,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching TIP20 token burn events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchBurn({
 *     onBurn(args) {
 *       console.log('Burn:', args)
 *     },
 *   })
 *
 *   return <div>Watching for burns...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchBurn(parameters = {}) {
    const { enabled = true, onBurn, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onBurn)
            return;
        if (!token)
            return;
        return Actions.token.watchBurn(config, {
            ...rest,
            chainId,
            onBurn,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onBurn,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching new TIP20 tokens created.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchCreate({
 *     onTokenCreated(args) {
 *       console.log('Token created:', args)
 *     },
 *   })
 *
 *   return <div>Watching for token creations...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchCreate(parameters = {}) {
    const { enabled = true, onTokenCreated, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onTokenCreated)
            return;
        return Actions.token.watchCreate(config, {
            ...rest,
            chainId,
            onTokenCreated,
        });
    }, [
        config,
        enabled,
        chainId,
        onTokenCreated,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching TIP20 token mint events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchMint({
 *     onMint(args) {
 *       console.log('Mint:', args)
 *     },
 *   })
 *
 *   return <div>Watching for mints...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchMint(parameters = {}) {
    const { enabled = true, onMint, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onMint)
            return;
        if (!token)
            return;
        return Actions.token.watchMint(config, {
            ...rest,
            chainId,
            onMint,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onMint,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching TIP20 token role membership updates.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchRole({
 *     onRoleUpdated(args) {
 *       console.log('Role updated:', args)
 *     },
 *   })
 *
 *   return <div>Watching for role updates...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchRole(parameters = {}) {
    const { enabled = true, onRoleUpdated, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onRoleUpdated)
            return;
        if (!token)
            return;
        return Actions.token.watchRole(config, {
            ...rest,
            chainId,
            onRoleUpdated,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onRoleUpdated,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching TIP20 token transfer events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchTransfer({
 *     onTransfer(args) {
 *       console.log('Transfer:', args)
 *     },
 *   })
 *
 *   return <div>Watching for transfers...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchTransfer(parameters = {}) {
    const { enabled = true, onTransfer, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onTransfer)
            return;
        if (!token)
            return;
        return Actions.token.watchTransfer(config, {
            ...rest,
            chainId,
            onTransfer,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onTransfer,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
/**
 * Hook for watching TIP20 token quote token update events.
 *
 * @example
 * ```tsx
 * import { Hooks } from 'wagmi/tempo'
 *
 * function App() {
 *   Hooks.token.useWatchUpdateQuoteToken({
 *     onUpdateQuoteToken(args) {
 *       if (args.completed)
 *         console.log('quote token update completed:', args.newQuoteToken)
 *       else
 *         console.log('quote token update proposed:', args.newQuoteToken)
 *     },
 *   })
 *
 *   return <div>Watching for quote token updates...</div>
 * }
 * ```
 *
 * @param parameters - Parameters.
 */
export function useWatchUpdateQuoteToken(parameters = {}) {
    const { enabled = true, onUpdateQuoteToken, token, ...rest } = parameters;
    const config = useConfig({ config: parameters.config });
    const configChainId = useChainId({ config });
    const chainId = parameters.chainId ?? configChainId;
    // biome-ignore lint/correctness/useExhaustiveDependencies: rest.x is explicitly listed
    useEffect(() => {
        if (!enabled)
            return;
        if (!onUpdateQuoteToken)
            return;
        if (!token)
            return;
        return Actions.token.watchUpdateQuoteToken(config, {
            ...rest,
            chainId,
            onUpdateQuoteToken,
            token,
        });
    }, [
        config,
        enabled,
        chainId,
        token,
        onUpdateQuoteToken,
        rest.fromBlock,
        rest.onError,
        rest.poll,
        rest.pollingInterval,
    ]);
}
//# sourceMappingURL=token.js.map