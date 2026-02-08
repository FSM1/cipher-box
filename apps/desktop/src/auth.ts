/**
 * CipherBox Desktop - Webview Auth Module
 *
 * Initializes Web3Auth inside the Tauri webview and provides login/logout
 * functions. After Web3Auth authentication, credentials are passed to the
 * Rust backend via Tauri IPC commands (secure in-process channel).
 *
 * The private key never leaves the process -- it stays within the webview
 * and is passed to Rust via invoke(), not URL parameters or deep links.
 */

import { invoke } from '@tauri-apps/api/core';
import {
  Web3Auth,
  WEB3AUTH_NETWORK,
  WALLET_CONNECTORS,
  type Web3AuthOptions,
} from '@web3auth/modal';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let web3auth: any = null;

// Web3Auth configuration matching the web app (apps/web/src/lib/web3auth/config.ts)
const WEB3AUTH_CLIENT_ID = import.meta.env.VITE_WEB3AUTH_CLIENT_ID || '';

// Custom OAuth connection IDs (configured in Web3Auth dashboard)
const AUTH_CONNECTION_IDS = {
  GOOGLE: 'cipherbox-google-oauth-2',
  EMAIL: 'cb-email-testnet',
  GROUP: 'cipherbox-grouped-connection',
} as const;

/**
 * Initialize the Web3Auth SDK.
 *
 * Must be called once before login(). Sets up the Web3Auth modal
 * with the same configuration as the web app.
 */
export async function initWeb3Auth(): Promise<void> {
  if (web3auth) return; // Already initialized

  try {
    const options: Web3AuthOptions = {
      clientId: WEB3AUTH_CLIENT_ID,
      web3AuthNetwork: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
      uiConfig: {
        mode: 'dark',
      },
      modalConfig: {
        connectors: {
          [WALLET_CONNECTORS.AUTH]: {
            label: 'auth',
            loginMethods: {
              google: {
                name: 'Google',
                showOnModal: true,
                authConnectionId: AUTH_CONNECTION_IDS.GOOGLE,
                groupedAuthConnectionId: AUTH_CONNECTION_IDS.GROUP,
              },
              email_passwordless: {
                name: 'Email',
                showOnModal: true,
                authConnectionId: AUTH_CONNECTION_IDS.EMAIL,
                groupedAuthConnectionId: AUTH_CONNECTION_IDS.GROUP,
              },
            },
            showOnModal: true,
          },
          [WALLET_CONNECTORS.WALLET_CONNECT_V2]: {
            label: 'WalletConnect',
            showOnModal: true,
          },
          [WALLET_CONNECTORS.METAMASK]: {
            label: 'MetaMask',
            showOnModal: true,
          },
        },
      },
    };

    web3auth = new Web3Auth(options);
    await web3auth.init();
    console.log('Web3Auth initialized');
  } catch (err) {
    console.error('Failed to initialize Web3Auth:', err);
    throw err;
  }
}

/**
 * Trigger Web3Auth login flow.
 *
 * Opens the Web3Auth modal inside the Tauri webview. After successful
 * authentication:
 * 1. Extracts the idToken from Web3Auth
 * 2. Extracts the private key from the Web3Auth provider
 * 3. Passes both to the Rust backend via Tauri IPC (handle_auth_complete)
 *
 * The Rust side then:
 * - Sends idToken to the CipherBox backend for access/refresh tokens
 * - Stores refresh token in macOS Keychain
 * - Decrypts vault keys (including root IPNS keypair)
 */
export async function login(): Promise<void> {
  if (!web3auth) {
    throw new Error('Web3Auth not initialized. Call initWeb3Auth() first.');
  }

  // Open Web3Auth modal -- user picks login method
  const provider = await web3auth.connect();
  if (!provider) {
    throw new Error('Web3Auth connection failed: no provider returned');
  }

  // Extract idToken (v10 API: getIdentityToken() returns { idToken })
  const tokenInfo = await web3auth.getIdentityToken();
  if (!tokenInfo?.idToken) {
    throw new Error('Failed to get idToken from Web3Auth');
  }
  const idToken: string = tokenInfo.idToken;

  // Extract private key from provider
  // Web3Auth social logins expose the private key via RPC
  let privateKey: string | null = null;
  try {
    privateKey = await provider.request<unknown, string>({ method: 'private_key' });
  } catch {
    // Fallback for some provider versions
    try {
      privateKey = await provider.request<unknown, string>({ method: 'eth_private_key' });
    } catch {
      throw new Error('Failed to extract private key from Web3Auth provider');
    }
  }

  if (!privateKey) {
    throw new Error('No private key returned from Web3Auth provider');
  }

  // Remove 0x prefix if present for consistent hex format
  const privateKeyHex = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;

  // Pass credentials to Rust backend via Tauri IPC
  // This is a secure in-process channel -- no URL parameters or external communication
  await invoke('handle_auth_complete', {
    idToken,
    privateKey: privateKeyHex,
  });

  console.log('Authentication complete -- credentials passed to Rust backend');
}

/**
 * Logout from Web3Auth and clear Rust-side state.
 *
 * Calls the Rust logout command first (clears Keychain, zeros keys),
 * then disconnects from Web3Auth.
 */
export async function logout(): Promise<void> {
  // Clear Rust-side state (Keychain, memory keys)
  await invoke('logout');

  // Disconnect from Web3Auth
  if (web3auth?.connected) {
    try {
      await web3auth.logout();
    } catch (err) {
      // Best-effort -- don't fail logout if Web3Auth cleanup fails
      console.warn('Web3Auth logout error (continuing):', err);
    }
  }

  console.log('Logout complete');
}

/**
 * Check if Web3Auth is currently connected.
 */
export function isConnected(): boolean {
  return web3auth?.connected ?? false;
}
