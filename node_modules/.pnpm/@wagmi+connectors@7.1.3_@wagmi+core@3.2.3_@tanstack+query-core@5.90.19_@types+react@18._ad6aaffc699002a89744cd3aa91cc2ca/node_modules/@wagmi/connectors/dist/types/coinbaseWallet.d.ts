import type { createCoinbaseWalletSDK, ProviderInterface } from '@coinbase/wallet-sdk';
import type { Mutable, Omit } from '@wagmi/core/internal';
import { type Address } from 'viem';
export type CoinbaseWalletParameters<
/** @deprecated remove */
_ = unknown> = Mutable<Omit<Parameters<typeof createCoinbaseWalletSDK>[0], 'appChainIds'>>;
export declare function coinbaseWallet(parameters?: CoinbaseWalletParameters): import("@wagmi/core").CreateConnectorFn<ProviderInterface & {
    close?(): void;
}, {
    connect<withCapabilities extends boolean = false>(parameters?: {
        chainId?: number | undefined;
        instantOnboarding?: boolean | undefined;
        isReconnecting?: boolean | undefined;
        withCapabilities?: withCapabilities | boolean | undefined;
    }): Promise<{
        accounts: withCapabilities extends true ? readonly {
            address: Address;
        }[] : readonly Address[];
        chainId: number;
    }>;
}, Record<string, unknown>>;
export declare namespace coinbaseWallet {
    var type: "coinbaseWallet";
}
//# sourceMappingURL=coinbaseWallet.d.ts.map