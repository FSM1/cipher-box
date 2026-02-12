import * as Address from 'ox/Address';
import { KeyAuthorization } from 'ox/tempo';
import { type LocalAccount } from 'viem/accounts';
import { WebAuthnP256 } from 'viem/tempo';
import type { OneOf } from '../types/utils.js';
import type * as KeyManager from './KeyManager.js';
/** @deprecated use `webAuthn.Parameters` instead */
export type WebAuthnParameters = webAuthn.Parameters;
/**
 * Connector for a WebAuthn EOA.
 */
export declare function webAuthn(options: webAuthn.Parameters): import("../connectors/createConnector.js").CreateConnectorFn<Pick<{
    on: <event extends keyof import("viem").EIP1193EventMap>(event: event, listener: import("viem").EIP1193EventMap[event]) => void;
    removeListener: <event extends keyof import("viem").EIP1193EventMap>(event: event, listener: import("viem").EIP1193EventMap[event]) => void;
    request: import("viem").EIP1193RequestFn<import("viem").EIP1474Methods>;
}, "request">, {
    connect<withCapabilities extends boolean = false>(parameters: {
        chainId?: number | undefined;
        capabilities?: OneOf<{
            label?: string | undefined;
            type: "sign-up";
        } | {
            selectAccount?: boolean | undefined;
            type: "sign-in";
        } | {
            type?: undefined;
        }> | undefined;
        isReconnecting?: boolean | undefined;
        withCapabilities?: withCapabilities | boolean | undefined;
    }): Promise<{
        accounts: readonly Address.Address[];
        chainId: number;
    }>;
}, {
    [key: `pendingKeyAuthorization:${string}`]: KeyAuthorization.KeyAuthorization<boolean, bigint, number>;
    'webAuthn.activeCredential': WebAuthnP256.P256Credential;
    'webAuthn.lastActiveCredential': WebAuthnP256.P256Credential;
}>;
export declare namespace webAuthn {
    var type: "webAuthn";
}
export declare namespace webAuthn {
    type Parameters = {
        /** Options for WebAuthn registration. */
        createOptions?: Pick<WebAuthnP256.createCredential.Parameters, 'createFn' | 'label' | 'rpId' | 'userId' | 'timeout'> | undefined;
        /** Options for WebAuthn authentication. */
        getOptions?: Pick<WebAuthnP256.getCredential.Parameters, 'getFn' | 'rpId'> | undefined;
        /**
         * Whether or not to grant an access key upon connection, and optionally, expiry + limits to assign to the key.
         */
        grantAccessKey?: boolean | (Pick<KeyAuthorization.KeyAuthorization, 'expiry' | 'limits'> & {
            /** Whether or not to throw an error and disconnect if the access key is not provisioned or is expired. */
            strict?: boolean | undefined;
        });
        /** Public key manager. */
        keyManager: KeyManager.KeyManager;
        /** The RP ID to use for WebAuthn. */
        rpId?: string | undefined;
    };
}
/** @deprecated use `dangerous_secp256k1.Parameters` instead */
export type Dangerous_Secp256k1Parameters = dangerous_secp256k1.Parameters;
/**
 * Connector for a Secp256k1 EOA.
 *
 * WARNING: NOT RECOMMENDED FOR PRODUCTION USAGE.
 * This connector stores private keys in clear text, and are bound to the session
 * length of the storage used.
 */
export declare function dangerous_secp256k1(options?: dangerous_secp256k1.Parameters): import("../connectors/createConnector.js").CreateConnectorFn<Pick<{
    on: <event extends keyof import("viem").EIP1193EventMap>(event: event, listener: import("viem").EIP1193EventMap[event]) => void;
    removeListener: <event extends keyof import("viem").EIP1193EventMap>(event: event, listener: import("viem").EIP1193EventMap[event]) => void;
    request: import("viem").EIP1193RequestFn<import("viem").EIP1474Methods>;
}, "request">, {
    connect<withCapabilities extends boolean = false>(parameters: {
        capabilities?: {
            type?: "sign-up" | undefined;
        } | undefined;
        chainId?: number | undefined;
        isReconnecting?: boolean | undefined;
        withCapabilities?: withCapabilities | boolean | undefined;
    }): Promise<{
        accounts: readonly Address.Address[];
        chainId: number;
    }>;
}, {
    [key: `secp256k1.${string}.privateKey`]: `0x${string}`;
    'secp256k1.activeAddress': Address.Address;
    'secp256k1.lastActiveAddress': Address.Address;
}>;
export declare namespace dangerous_secp256k1 {
    var type: "dangerous_secp256k1";
}
export declare namespace dangerous_secp256k1 {
    type Parameters = {
        account?: LocalAccount | undefined;
    };
}
//# sourceMappingURL=Connectors.d.ts.map