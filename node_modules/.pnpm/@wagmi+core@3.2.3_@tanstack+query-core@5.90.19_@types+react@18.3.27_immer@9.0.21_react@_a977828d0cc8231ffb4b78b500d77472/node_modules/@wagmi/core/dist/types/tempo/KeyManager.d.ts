import type { WebAuthnP256 } from 'ox';
import type * as Hex from 'ox/Hex';
import { type CreateStorageParameters, type Storage } from '../createStorage.js';
export type KeyManager = {
    /** Function to fetch create options for WebAuthn. */
    getChallenge?: (() => Promise<{
        challenge: Hex.Hex;
        rp?: {
            id: string;
            name: string;
        } | undefined;
    }>) | undefined;
    /** Function to fetch the public key for a credential. */
    getPublicKey: (parameters: {
        credential: WebAuthnP256.P256Credential['raw'];
    }) => Promise<Hex.Hex>;
    /** Function to set the public key for a credential. */
    setPublicKey: (parameters: {
        credential: WebAuthnP256.P256Credential['raw'];
        publicKey: Hex.Hex;
    }) => Promise<void>;
};
/** Instantiates a key manager. */
export declare function from<manager extends KeyManager>(manager: manager): manager;
/** Instantiates a key manager from a Storage instance. */
export declare function fromStorage(storage: Storage): KeyManager;
/**
 * Instantiates a key manager from a localStorage instance.
 *
 * WARNING: Do not use this in production.
 * This is because we are unable to extract a user's public key after the registration
 * process. If a user clears their storage, or visits the website on a different device,
 * they will not be able to access their account.
 *
 * Instead, we recommend to set up a remote store such as [`KeyManager.http`](#http) to register
 * public keys against their WebAuthn credential.
 *
 * @see {@link http}
 *
 * @deprecated
 */
export declare function localStorage(options?: localStorage.Options): KeyManager;
export declare namespace localStorage {
    type Options = Omit<CreateStorageParameters, 'storage'>;
}
/**
 * Instantiates a key manager that uses HTTP endpoints for credential management.
 *
 * @example
 * ```tsx
 * import { KeyManager } from '@wagmi/core/tempo'
 *
 * const keyManager = KeyManager.http('https://api.example.com')
 * ```
 *
 * @param url - The URL to use for the HTTP endpoints.
 * @param options - Configuration options for HTTP endpoints.
 * @returns A KeyManager instance that uses HTTP for credential operations.
 */
export declare function http(url: string | {
    getChallenge?: string | Request | undefined;
    getPublicKey?: string | Request | undefined;
    setPublicKey?: string | Request | undefined;
}, options?: http.Options): KeyManager;
export declare namespace http {
    type Options = {
        /** Custom fetch function. @default `globalThis.fetch`. */
        fetch?: typeof fetch | undefined;
    };
}
//# sourceMappingURL=KeyManager.d.ts.map