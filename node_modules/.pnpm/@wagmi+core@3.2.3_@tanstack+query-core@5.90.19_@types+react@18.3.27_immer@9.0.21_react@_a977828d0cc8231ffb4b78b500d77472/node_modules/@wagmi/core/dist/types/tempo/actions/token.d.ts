import type { Account, BaseErrorType } from 'viem';
import { Actions } from 'viem/tempo';
import type { Config } from '../../createConfig.js';
import type { ChainIdParameter, ConnectorParameter } from '../../types/properties.js';
import type { UnionLooseOmit } from '../../types/utils.js';
import type { QueryOptions, QueryParameter } from './utils.js';
/**
 * Approves a spender to transfer TIP20 tokens on behalf of the caller.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { Actions } from '@wagmi/core/tempo'
 * import { tempo } from '@wagmi/core/chains'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.approve(config, {
 *   spender: '0x...',
 *   amount: 100n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function approve<config extends Config>(config: config, parameters: approve.Parameters<config>): Promise<Actions.token.approve.ReturnValue>;
export declare namespace approve {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.approve.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.approve.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Approves a spender to transfer TIP20 tokens on behalf of the caller.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.approveSync(config, {
 *   spender: '0x...',
 *   amount: 100n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function approveSync<config extends Config>(config: config, parameters: approveSync.Parameters<config>): Promise<Actions.token.approveSync.ReturnValue>;
export declare namespace approveSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.approveSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.approveSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Burns TIP20 tokens from the caller's balance.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.burn(config, {
 *   amount: 100n,
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function burn<config extends Config>(config: config, parameters: burn.Parameters<config>): Promise<Actions.token.burn.ReturnValue>;
export declare namespace burn {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.burn.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.burn.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Burns TIP20 tokens from a blocked address.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.burnBlocked(config, {
 *   from: '0x...',
 *   amount: 100n,
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function burnBlocked<config extends Config>(config: config, parameters: burnBlocked.Parameters<config>): Promise<Actions.token.burnBlocked.ReturnValue>;
export declare namespace burnBlocked {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.burnBlocked.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.burnBlocked.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Burns TIP20 tokens from a blocked address.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.burnBlockedSync(config, {
 *   from: '0x...',
 *   amount: 100n,
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function burnBlockedSync<config extends Config>(config: config, parameters: burnBlockedSync.Parameters<config>): Promise<Actions.token.burnBlockedSync.ReturnValue>;
export declare namespace burnBlockedSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.burnBlockedSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.burnBlockedSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Burns TIP20 tokens from the caller's balance.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.burnSync(config, {
 *   amount: 100n,
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function burnSync<config extends Config>(config: config, parameters: burnSync.Parameters<config>): Promise<Actions.token.burnSync.ReturnValue>;
export declare namespace burnSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.burnSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.burnSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Changes the transfer policy ID for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.changeTransferPolicy(config, {
 *   token: '0x...',
 *   policyId: 1n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function changeTransferPolicy<config extends Config>(config: config, parameters: changeTransferPolicy.Parameters<config>): Promise<Actions.token.changeTransferPolicy.ReturnValue>;
export declare namespace changeTransferPolicy {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.changeTransferPolicy.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.changeTransferPolicy.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Changes the transfer policy ID for a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.changeTransferPolicySync(config, {
 *   token: '0x...',
 *   policyId: 1n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function changeTransferPolicySync<config extends Config>(config: config, parameters: changeTransferPolicySync.Parameters<config>): Promise<Actions.token.changeTransferPolicySync.ReturnValue>;
export declare namespace changeTransferPolicySync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.changeTransferPolicySync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.changeTransferPolicySync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Creates a new TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.create(config, {
 *   name: 'My Token',
 *   symbol: 'MTK',
 *   currency: 'USD',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function create<config extends Config>(config: config, parameters: create.Parameters<config>): Promise<Actions.token.create.ReturnValue>;
export declare namespace create {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.create.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.create.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Creates a new TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.createSync(config, {
 *   name: 'My Token',
 *   symbol: 'MTK',
 *   currency: 'USD',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function createSync<config extends Config>(config: config, parameters: createSync.Parameters<config>): Promise<Actions.token.createSync.ReturnValue>;
export declare namespace createSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.createSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.createSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Updates the quote token for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.updateQuoteToken(config, {
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function updateQuoteToken<config extends Config>(config: config, parameters: updateQuoteToken.Parameters<config>): Promise<Actions.token.updateQuoteToken.ReturnValue>;
export declare namespace updateQuoteToken {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.updateQuoteToken.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.updateQuoteToken.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Updates the quote token for a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.updateQuoteTokenSync(config, {
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function updateQuoteTokenSync<config extends Config>(config: config, parameters: updateQuoteTokenSync.Parameters<config>): Promise<Actions.token.updateQuoteTokenSync.ReturnValue>;
export declare namespace updateQuoteTokenSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.updateQuoteTokenSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.updateQuoteTokenSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Gets TIP20 token allowance.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const allowance = await Actions.token.getAllowance(config, {
 *   account: '0x...',
 *   spender: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The token allowance.
 */
export declare function getAllowance<config extends Config>(config: config, parameters: getAllowance.Parameters<config>): Promise<getAllowance.ReturnValue>;
export declare namespace getAllowance {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.getAllowance.Parameters;
    type ReturnValue = Actions.token.getAllowance.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getAllowance", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getAllowance.ReturnValue> = getAllowance.Parameters<config> & QueryParameter<getAllowance.ReturnValue, getAllowance.ErrorType, selectData, getAllowance.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getAllowance.ReturnValue> = QueryOptions<getAllowance.ReturnValue, getAllowance.ErrorType, selectData, getAllowance.QueryKey<config>>;
    }
}
/**
 * Gets TIP20 token balance for an address.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const balance = await Actions.token.getBalance(config, {
 *   account: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The token balance.
 */
export declare function getBalance<config extends Config>(config: config, parameters: getBalance.Parameters<config>): Promise<getBalance.ReturnValue>;
export declare namespace getBalance {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.getBalance.Parameters;
    type ReturnValue = Actions.token.getBalance.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getBalance", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getBalance.ReturnValue> = getBalance.Parameters<config> & QueryParameter<getBalance.ReturnValue, getBalance.ErrorType, selectData, getBalance.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getBalance.ReturnValue> = QueryOptions<getBalance.ReturnValue, getBalance.ErrorType, selectData, getBalance.QueryKey<config>>;
    }
}
/**
 * Gets TIP20 token metadata.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const metadata = await Actions.token.getMetadata(config, {
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The token metadata.
 */
export declare function getMetadata<config extends Config>(config: config, parameters: getMetadata.Parameters<config>): Promise<getMetadata.ReturnValue>;
export declare namespace getMetadata {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.getMetadata.Parameters;
    type ReturnValue = Actions.token.getMetadata.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getMetadata", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getMetadata.ReturnValue> = getMetadata.Parameters<config> & QueryParameter<getMetadata.ReturnValue, getMetadata.ErrorType, selectData, getMetadata.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getMetadata.ReturnValue> = QueryOptions<getMetadata.ReturnValue, getMetadata.ErrorType, selectData, getMetadata.QueryKey<config>>;
    }
}
/**
 * Gets the admin role for a specific role in a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const adminRole = await Actions.token.getRoleAdmin(config, {
 *   role: 'issuer',
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The admin role hash.
 */
export declare function getRoleAdmin<config extends Config>(config: config, parameters: getRoleAdmin.Parameters<config>): Promise<getRoleAdmin.ReturnValue>;
export declare namespace getRoleAdmin {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.getRoleAdmin.Parameters;
    type ReturnValue = Actions.token.getRoleAdmin.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["getRoleAdmin", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = getRoleAdmin.ReturnValue> = getRoleAdmin.Parameters<config> & QueryParameter<getRoleAdmin.ReturnValue, getRoleAdmin.ErrorType, selectData, getRoleAdmin.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = getRoleAdmin.ReturnValue> = QueryOptions<getRoleAdmin.ReturnValue, getRoleAdmin.ErrorType, selectData, getRoleAdmin.QueryKey<config>>;
    }
}
/**
 * Grants a role for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.grantRoles(config, {
 *   token: '0x...',
 *   to: '0x...',
 *   roles: ['issuer'],
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function grantRoles<config extends Config>(config: config, parameters: grantRoles.Parameters<config>): Promise<Actions.token.grantRoles.ReturnValue>;
export declare namespace grantRoles {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.grantRoles.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.grantRoles.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Grants a role for a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.grantRolesSync(config, {
 *   token: '0x...',
 *   to: '0x...',
 *   roles: ['issuer'],
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function grantRolesSync<config extends Config>(config: config, parameters: grantRolesSync.Parameters<config>): Promise<Actions.token.grantRolesSync.ReturnValue>;
export declare namespace grantRolesSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.grantRolesSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.grantRolesSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Checks if an account has a specific role for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hasRole = await Actions.token.hasRole(config, {
 *   account: '0x...',
 *   role: 'issuer',
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Whether the account has the role.
 */
export declare function hasRole<config extends Config>(config: config, parameters: hasRole.Parameters<config>): Promise<hasRole.ReturnValue>;
export declare namespace hasRole {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.hasRole.Parameters;
    type ReturnValue = Actions.token.hasRole.ReturnValue;
    type ErrorType = BaseErrorType;
    function queryKey<config extends Config>(parameters: Parameters<config>): readonly ["hasRole", Parameters<config>];
    type QueryKey<config extends Config> = ReturnType<typeof queryKey<config>>;
    function queryOptions<config extends Config, selectData = ReturnValue>(config: Config, parameters: queryOptions.Parameters<config, selectData>): queryOptions.ReturnValue<config, selectData>;
    namespace queryOptions {
        type Parameters<config extends Config, selectData = hasRole.ReturnValue> = hasRole.Parameters<config> & QueryParameter<hasRole.ReturnValue, hasRole.ErrorType, selectData, hasRole.QueryKey<config>>;
        type ReturnValue<config extends Config, selectData = hasRole.ReturnValue> = QueryOptions<hasRole.ReturnValue, hasRole.ErrorType, selectData, hasRole.QueryKey<config>>;
    }
}
/**
 * Mints TIP20 tokens to an address.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.mint(config, {
 *   to: '0x...',
 *   amount: 100n,
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function mint<config extends Config>(config: config, parameters: mint.Parameters<config>): Promise<Actions.token.mint.ReturnValue>;
export declare namespace mint {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.mint.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.mint.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Mints TIP20 tokens to an address.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.mintSync(config, {
 *   to: '0x...',
 *   amount: 100n,
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function mintSync<config extends Config>(config: config, parameters: mintSync.Parameters<config>): Promise<Actions.token.mintSync.ReturnValue>;
export declare namespace mintSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.mintSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.mintSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Pauses a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.pause(config, {
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function pause<config extends Config>(config: config, parameters: pause.Parameters<config>): Promise<Actions.token.pause.ReturnValue>;
export declare namespace pause {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.pause.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.pause.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Pauses a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.pauseSync(config, {
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function pauseSync<config extends Config>(config: config, parameters: pauseSync.Parameters<config>): Promise<Actions.token.pauseSync.ReturnValue>;
export declare namespace pauseSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.pauseSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.pauseSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Renounces a role for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.renounceRoles(config, {
 *   token: '0x...',
 *   roles: ['issuer'],
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function renounceRoles<config extends Config>(config: config, parameters: renounceRoles.Parameters<config>): Promise<Actions.token.renounceRoles.ReturnValue>;
export declare namespace renounceRoles {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.renounceRoles.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.renounceRoles.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Renounces a role for a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.renounceRolesSync(config, {
 *   token: '0x...',
 *   roles: ['issuer'],
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function renounceRolesSync<config extends Config>(config: config, parameters: renounceRolesSync.Parameters<config>): Promise<Actions.token.renounceRolesSync.ReturnValue>;
export declare namespace renounceRolesSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.renounceRolesSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.renounceRolesSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Revokes a role for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.revokeRoles(config, {
 *   token: '0x...',
 *   from: '0x...',
 *   roles: ['issuer'],
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function revokeRoles<config extends Config>(config: config, parameters: revokeRoles.Parameters<config>): Promise<Actions.token.revokeRoles.ReturnValue>;
export declare namespace revokeRoles {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.revokeRoles.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.revokeRoles.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Revokes a role for a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.revokeRolesSync(config, {
 *   token: '0x...',
 *   from: '0x...',
 *   roles: ['issuer'],
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function revokeRolesSync<config extends Config>(config: config, parameters: revokeRolesSync.Parameters<config>): Promise<Actions.token.revokeRolesSync.ReturnValue>;
export declare namespace revokeRolesSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.revokeRolesSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.revokeRolesSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Sets the admin role for a specific role in a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.setRoleAdmin(config, {
 *   token: '0x...',
 *   role: 'issuer',
 *   adminRole: 'pause',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function setRoleAdmin<config extends Config>(config: config, parameters: setRoleAdmin.Parameters<config>): Promise<Actions.token.setRoleAdmin.ReturnValue>;
export declare namespace setRoleAdmin {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.setRoleAdmin.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.setRoleAdmin.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Sets the admin role for a specific role in a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.setRoleAdminSync(config, {
 *   token: '0x...',
 *   role: 'issuer',
 *   adminRole: 'pause',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function setRoleAdminSync<config extends Config>(config: config, parameters: setRoleAdminSync.Parameters<config>): Promise<Actions.token.setRoleAdminSync.ReturnValue>;
export declare namespace setRoleAdminSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.setRoleAdminSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.setRoleAdminSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Sets the supply cap for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.setSupplyCap(config, {
 *   token: '0x...',
 *   supplyCap: 1000000n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function setSupplyCap<config extends Config>(config: config, parameters: setSupplyCap.Parameters<config>): Promise<Actions.token.setSupplyCap.ReturnValue>;
export declare namespace setSupplyCap {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.setSupplyCap.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.setSupplyCap.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Sets the supply cap for a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.setSupplyCapSync(config, {
 *   token: '0x...',
 *   supplyCap: 1000000n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function setSupplyCapSync<config extends Config>(config: config, parameters: setSupplyCapSync.Parameters<config>): Promise<Actions.token.setSupplyCapSync.ReturnValue>;
export declare namespace setSupplyCapSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.setSupplyCapSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.setSupplyCapSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Transfers TIP20 tokens to another address.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.transfer(config, {
 *   to: '0x...',
 *   amount: 100n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function transfer<config extends Config>(config: config, parameters: transfer.Parameters<config>): Promise<Actions.token.transfer.ReturnValue>;
export declare namespace transfer {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.transfer.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.transfer.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Transfers TIP20 tokens to another address.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.transferSync(config, {
 *   to: '0x...',
 *   amount: 100n,
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function transferSync<config extends Config>(config: config, parameters: transferSync.Parameters<config>): Promise<Actions.token.transferSync.ReturnValue>;
export declare namespace transferSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.transferSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.transferSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Unpauses a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.unpause(config, {
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function unpause<config extends Config>(config: config, parameters: unpause.Parameters<config>): Promise<Actions.token.unpause.ReturnValue>;
export declare namespace unpause {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.unpause.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.unpause.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Unpauses a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.unpauseSync(config, {
 *   token: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function unpauseSync<config extends Config>(config: config, parameters: unpauseSync.Parameters<config>): Promise<Actions.token.unpauseSync.ReturnValue>;
export declare namespace unpauseSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.unpauseSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.unpauseSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Prepares the quote token update for a TIP20 token.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const hash = await Actions.token.prepareUpdateQuoteToken(config, {
 *   token: '0x...',
 *   quoteToken: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns Transaction hash.
 */
export declare function prepareUpdateQuoteToken<config extends Config>(config: config, parameters: prepareUpdateQuoteToken.Parameters<config>): Promise<Actions.token.prepareUpdateQuoteToken.ReturnValue>;
export declare namespace prepareUpdateQuoteToken {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.prepareUpdateQuoteToken.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.prepareUpdateQuoteToken.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Prepares the quote token update for a TIP20 token.
 *
 * Note: This is a synchronous action that waits for the transaction to
 * be included on a block before returning a response.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const result = await Actions.token.prepareUpdateQuoteTokenSync(config, {
 *   token: '0x...',
 *   quoteToken: '0x...',
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export declare function prepareUpdateQuoteTokenSync<config extends Config>(config: config, parameters: prepareUpdateQuoteTokenSync.Parameters<config>): Promise<Actions.token.prepareUpdateQuoteTokenSync.ReturnValue>;
export declare namespace prepareUpdateQuoteTokenSync {
    type Parameters<config extends Config> = ChainIdParameter<config> & ConnectorParameter & UnionLooseOmit<Actions.token.prepareUpdateQuoteTokenSync.Parameters<config['chains'][number], Account>, 'chain'>;
    type ReturnValue = Actions.token.prepareUpdateQuoteTokenSync.ReturnValue;
    type ErrorType = BaseErrorType;
}
/**
 * Watches for TIP20 token role admin updates.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchAdminRole(config, {
 *   onRoleAdminUpdated: (args, log) => {
 *     console.log('Role admin updated:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchAdminRole<config extends Config>(config: config, parameters: watchAdminRole.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchAdminRole {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchAdminRole.Parameters;
}
/**
 * Watches for TIP20 token approval events.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchApprove(config, {
 *   onApproval: (args, log) => {
 *     console.log('Approval:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchApprove<config extends Config>(config: config, parameters: watchApprove.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchApprove {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchApprove.Parameters;
}
/**
 * Watches for TIP20 token burn events.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchBurn(config, {
 *   onBurn: (args, log) => {
 *     console.log('Burn:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchBurn<config extends Config>(config: config, parameters: watchBurn.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchBurn {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchBurn.Parameters;
}
/**
 * Watches for new TIP20 tokens created.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchCreate(config, {
 *   onTokenCreated: (args, log) => {
 *     console.log('Token created:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchCreate<config extends Config>(config: config, parameters: watchCreate.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchCreate {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchCreate.Parameters;
}
/**
 * Watches for TIP20 token mint events.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchMint(config, {
 *   onMint: (args, log) => {
 *     console.log('Mint:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchMint<config extends Config>(config: config, parameters: watchMint.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchMint {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchMint.Parameters;
    type ReturnValue = Actions.token.watchMint.ReturnValue;
}
/**
 * Watches for TIP20 token role membership updates.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchRole(config, {
 *   onRoleUpdated: (args, log) => {
 *     console.log('Role updated:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchRole<config extends Config>(config: config, parameters: watchRole.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchRole {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchRole.Parameters;
}
/**
 * Watches for TIP20 token transfer events.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchTransfer(config, {
 *   onTransfer: (args, log) => {
 *     console.log('Transfer:', args)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchTransfer<config extends Config>(config: config, parameters: watchTransfer.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchTransfer {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchTransfer.Parameters;
}
/**
 * Watches for TIP20 token quote token update events.
 *
 * @example
 * ```ts
 * import { createConfig, http } from '@wagmi/core'
 * import { tempo } from '@wagmi/core/chains'
 * import { Actions } from '@wagmi/core/tempo'
 *
 * const config = createConfig({
 *   chains: [tempo],
 *   transports: {
 *     [tempo.id]: http(),
 *   },
 * })
 *
 * const unwatch = Actions.token.watchUpdateQuoteToken(config, {
 *   onUpdateQuoteToken: (args, log) => {
 *     if (args.completed)
 *       console.log('quote token update completed:', args.newQuoteToken)
 *     else
 *       console.log('quote token update proposed:', args.newQuoteToken)
 *   },
 * })
 * ```
 *
 * @param config - Config.
 * @param parameters - Parameters.
 * @returns A function to unsubscribe from the event.
 */
export declare function watchUpdateQuoteToken<config extends Config>(config: config, parameters: watchUpdateQuoteToken.Parameters<config>): import("viem").WatchContractEventReturnType;
export declare namespace watchUpdateQuoteToken {
    type Parameters<config extends Config> = ChainIdParameter<config> & Actions.token.watchUpdateQuoteToken.Parameters;
}
//# sourceMappingURL=token.d.ts.map