/**
 * SDK Provider - CipherBoxClient lifecycle management
 *
 * Manages a singleton CipherBoxClient instance for the web app.
 * Created after vault load (login complete), destroyed on logout.
 *
 * The SDK client is the single source of truth for all file operations.
 * Hooks call client methods, and stores subscribe to client events.
 */
import { CipherBoxClient, type CipherBoxClientConfig } from '@cipherbox/sdk';
import type { PinningConfig } from '@cipherbox/sdk';
import { apiAxios } from './api-config';
import { destroyEncryptionWorker } from '../services/encrypt-worker.service';

let _client: CipherBoxClient | null = null;
let _lastConfig: CipherBoxClientConfig | null = null;

/**
 * Initialize the SDK client. Called after vault is loaded (login complete).
 * The client persists for the session and is destroyed on logout.
 *
 * If a client already exists (e.g., session restoration), it is destroyed
 * before creating the new one.
 */
export function initSdkClient(config: CipherBoxClientConfig): CipherBoxClient {
  if (_client) {
    _client.destroy();
  }
  // Inject the shared axios instance so CipherBoxClient uses the same
  // instance as orval-generated functions (single instance, no dual path).
  _lastConfig = { ...config };
  _client = new CipherBoxClient({ ...config, axiosInstance: apiAxios });
  return _client;
}

/**
 * Get the current SDK client instance.
 * Throws if called before initSdkClient() (i.e., before login).
 */
export function getSdkClient(): CipherBoxClient {
  if (!_client) {
    throw new Error('SDK client not initialized. Call initSdkClient() after login.');
  }
  return _client;
}

/**
 * Check if the SDK client is initialized (for conditional usage).
 */
export function hasSdkClient(): boolean {
  return _client !== null;
}

/**
 * Destroy the SDK client. Called on logout.
 * Clears internal state, key caches, and event subscriptions.
 */
export function destroySdkClient(): void {
  if (_client) {
    _client.destroy();
    _client = null;
  }
  _lastConfig = null;
  // Terminate encryption Web Worker (no-op if not initialized)
  destroyEncryptionWorker();
}

/**
 * Reconfigure the SDK client's pinning config at runtime.
 * Called from StorageTab after saving new BYO settings.
 *
 * Destroys the current client and recreates it with updated pinningConfig
 * while preserving all other configuration. This is acceptable since config
 * changes are infrequent (only on Settings save).
 */
export function reconfigurePinning(pinningConfig?: PinningConfig): void {
  if (!_client || !_lastConfig) return;
  _client.destroy();
  _lastConfig = { ..._lastConfig, pinningConfig };
  _client = new CipherBoxClient({ ..._lastConfig, axiosInstance: apiAxios });
}

/**
 * Create a throwaway `CipherBoxClient` for facade calls that must run
 * BEFORE the real vault-scoped client exists -- vault-bootstrap crypto and
 * config-blob (BYO/vault-settings) resolve/publish during initial login,
 * when `rootIpnsName`/`rootFolderKey` aren't known yet (this client mints
 * or loads the very keys the real client needs to be constructed).
 *
 * The facade methods this is used for (`bootstrapVaultKeys`,
 * `serializeVault`/`deserializeVault`, `publishEmptyRootNode`,
 * `resolveConfigBlob`/`publishConfigBlob`, `uploadBytes`/`downloadBytes`)
 * only read `ctx` (apiUrl/getAccessToken/axiosInstance) or caller-supplied
 * key material passed directly as arguments -- they never touch
 * `rootIpnsName`/`rootFolderKey`/`folderTree`, so the placeholder values
 * below are never read. Callers MUST call `.destroy()` when finished to
 * zero this client's defensive key copies (D-09) -- it is a fully separate
 * instance from the module-level `_client`, so destroying it never affects
 * the real client.
 */
export function createBootstrapClient(config: {
  apiUrl: string;
  getAccessToken: () => Promise<string>;
  vaultKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
}): CipherBoxClient {
  return new CipherBoxClient({
    apiUrl: config.apiUrl,
    getAccessToken: config.getAccessToken,
    vaultKeypair: config.vaultKeypair,
    rootIpnsName: '',
    rootFolderKey: new Uint8Array(32),
    axiosInstance: apiAxios,
  });
}
