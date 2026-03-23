import type { Address, Chain } from 'viem';
import type { Config, Connector } from '../createConfig.js';
export type GetConnectionReturnType<config extends Config = Config, chain = Config extends config ? Chain : config['chains'][number]> = {
    address: Address;
    addresses: readonly [Address, ...Address[]];
    chain: chain | undefined;
    chainId: number;
    connector: Connector;
    isConnected: true;
    isConnecting: false;
    isDisconnected: false;
    isReconnecting: false;
    status: 'connected';
} | {
    address: Address | undefined;
    addresses: readonly Address[] | undefined;
    chain: chain | undefined;
    chainId: number | undefined;
    connector: Connector | undefined;
    isConnected: boolean;
    isConnecting: false;
    isDisconnected: false;
    isReconnecting: true;
    status: 'reconnecting';
} | {
    address: Address | undefined;
    addresses: readonly Address[] | undefined;
    chain: chain | undefined;
    chainId: number | undefined;
    connector: Connector | undefined;
    isConnected: false;
    isReconnecting: false;
    isConnecting: true;
    isDisconnected: false;
    status: 'connecting';
} | {
    address: undefined;
    addresses: undefined;
    chain: undefined;
    chainId: undefined;
    connector: undefined;
    isConnected: false;
    isReconnecting: false;
    isConnecting: false;
    isDisconnected: true;
    status: 'disconnected';
};
/** https://wagmi.sh/core/api/actions/getConnection */
export declare function getConnection<config extends Config>(config: config): GetConnectionReturnType<config>;
//# sourceMappingURL=getConnection.d.ts.map