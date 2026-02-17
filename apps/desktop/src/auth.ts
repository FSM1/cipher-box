/**
 * CipherBox Desktop - Webview Auth Module (Core Kit)
 *
 * Authenticates via CipherBox identity provider (Google OAuth, Email OTP),
 * then calls Core Kit loginWithJWT to derive the TSS key. After Core Kit
 * authentication, the CipherBox JWT and private key are passed to the
 * Rust backend via Tauri IPC commands (secure in-process channel).
 *
 * The private key never leaves the process -- it stays within the webview
 * and is passed to Rust via invoke(), not URL parameters or deep links.
 *
 * Auth flow:
 *   1. User authenticates via CipherBox backend (Google/Email)
 *   2. Backend issues a CipherBox JWT (RS256, iss=cipherbox, aud=web3auth)
 *   3. Frontend calls Core Kit loginWithJWT with the CipherBox JWT
 *   4. Core Kit derives TSS key -> _UNSAFE_exportTssKey -> private key hex
 *   5. Private key + CipherBox JWT passed to Rust via invoke('handle_auth_complete')
 */

import { invoke } from '@tauri-apps/api/core';
import { Web3AuthMPCCoreKit, WEB3AUTH_NETWORK, COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';

/** Minimal EIP-1193 provider interface for injected wallets (MetaMask etc.) */
interface EthereumProvider {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
}

// CipherBox API base URL (same as Rust backend uses)
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3000';
const WEB3AUTH_CLIENT_ID = import.meta.env.VITE_WEB3AUTH_CLIENT_ID || '';
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

const environment = import.meta.env.VITE_ENVIRONMENT || 'local';

const NETWORK_MAP: Record<string, (typeof WEB3AUTH_NETWORK)[keyof typeof WEB3AUTH_NETWORK]> = {
  local: WEB3AUTH_NETWORK.DEVNET,
  ci: WEB3AUTH_NETWORK.DEVNET,
  staging: WEB3AUTH_NETWORK.DEVNET,
  production: WEB3AUTH_NETWORK.MAINNET,
};

/** Minimal type declarations for Google Identity Services (GIS) library */
declare const google: {
  accounts: {
    id: {
      initialize: (config: {
        client_id: string;
        callback: (response: { credential: string }) => void;
        auto_select: boolean;
      }) => void;
      prompt: (
        momentListener?: (notification: {
          isNotDisplayed: () => boolean;
          isSkippedMoment: () => boolean;
        }) => void
      ) => void;
    };
  };
};

let coreKit: Web3AuthMPCCoreKit | null = null;

export type LoginResult = { status: 'logged_in' } | { status: 'required_share' };

/**
 * Initialize Core Kit singleton.
 * Must be called once before any login flow.
 * Matches the web app configuration exactly (same verifier, same network).
 */
export async function initCoreKit(): Promise<void> {
  if (coreKit) return;

  coreKit = new Web3AuthMPCCoreKit({
    web3AuthClientId: WEB3AUTH_CLIENT_ID,
    web3AuthNetwork: NETWORK_MAP[environment] || WEB3AUTH_NETWORK.DEVNET,
    storage: window.localStorage,
    manualSync: true,
    tssLib,
  });

  await coreKit.init();
  console.log('[CoreKit] Initialized, status:', coreKit.status);
}

/**
 * Get the current Core Kit status string.
 */
export function getCoreKitStatus(): string {
  return coreKit?.status || 'NOT_INITIALIZED';
}

/**
 * Login with Google via CipherBox identity provider.
 *
 * Flow:
 * 1. Load Google Identity Services (GIS) script in webview
 * 2. Get Google credential (JWT) via GIS prompt
 * 3. Send Google credential to CipherBox backend -> CipherBox JWT
 * 4. Core Kit loginWithJWT with CipherBox JWT
 * 5. Export TSS key and pass to Rust backend
 */
export async function loginWithGoogle(): Promise<LoginResult> {
  if (!coreKit) throw new Error('Core Kit not initialized');

  // 1. Get Google credential via Google Identity Services
  const googleIdToken = await getGoogleCredential();

  // 2. Send Google credential to CipherBox backend identity endpoint
  const resp = await fetch(`${API_BASE}/auth/identity/google`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken: googleIdToken }),
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Google auth failed (${resp.status}): ${body}`);
  }
  const { idToken: cipherboxJwt, userId } = await resp.json();

  // 3. Core Kit login + key export
  return await loginWithCoreKit(cipherboxJwt, userId);
}

/**
 * Request an email OTP from the CipherBox backend.
 * Returns immediately after the OTP is sent -- the user must check their email.
 */
export async function requestEmailOtp(email: string): Promise<void> {
  const resp = await fetch(`${API_BASE}/auth/identity/email/send-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.toLowerCase().trim() }),
  });
  if (!resp.ok) {
    if (resp.status === 429) {
      throw new Error('Too many attempts. Please wait before trying again.');
    }
    throw new Error('Failed to send verification code');
  }
}

/**
 * Verify an email OTP and complete login via Core Kit.
 *
 * Flow:
 * 1. Send email + OTP to CipherBox backend -> CipherBox JWT
 * 2. Core Kit loginWithJWT with CipherBox JWT
 * 3. Export TSS key and pass to Rust backend
 */
export async function loginWithEmailOtp(email: string, otp: string): Promise<LoginResult> {
  if (!coreKit) throw new Error('Core Kit not initialized');

  // 1. Verify OTP with CipherBox backend
  const resp = await fetch(`${API_BASE}/auth/identity/email/verify-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.toLowerCase().trim(), otp }),
  });
  if (!resp.ok) {
    if (resp.status === 401) {
      throw new Error('Invalid code. Please check and try again.');
    }
    throw new Error('OTP verification failed');
  }
  const { idToken: cipherboxJwt, userId } = await resp.json();

  // 2. Core Kit login + key export
  return await loginWithCoreKit(cipherboxJwt, userId);
}

/**
 * Login with an Ethereum wallet via SIWE (Sign-In with Ethereum).
 *
 * Flow:
 * 1. Detect injected wallet provider (window.ethereum)
 * 2. Request accounts via eth_requestAccounts
 * 3. Fetch SIWE nonce from CipherBox API
 * 4. Build EIP-4361 SIWE message (matching web app format exactly)
 * 5. Sign with personal_sign
 * 6. Verify signature on CipherBox API -> CipherBox JWT
 * 7. Core Kit loginWithJWT (same as Google/Email)
 *
 * Note: Tauri webview may not support browser wallet extensions.
 * If window.ethereum is not available, an informative error is shown.
 * WalletConnect QR code flow is deferred to Phase 11 (cross-platform).
 */
export async function loginWithWallet(): Promise<LoginResult> {
  if (!coreKit) throw new Error('Core Kit not initialized');

  // 1. Check for injected wallet provider
  const ethereum = (window as unknown as { ethereum?: EthereumProvider }).ethereum;
  if (!ethereum) {
    throw new Error(
      'No Ethereum wallet detected. Install a wallet browser extension to use wallet login.'
    );
  }

  // 2. Request accounts
  const accounts = (await ethereum.request({ method: 'eth_requestAccounts' })) as string[];
  if (!accounts || accounts.length === 0) {
    throw new Error('No wallet accounts available');
  }
  const address = accounts[0];

  // 3. Get SIWE nonce from CipherBox API
  const nonceResp = await fetch(`${API_BASE}/auth/identity/wallet/nonce`);
  if (!nonceResp.ok) throw new Error('Failed to get SIWE nonce');
  const { nonce } = await nonceResp.json();

  // 4. Create SIWE message (EIP-4361 format matching web app's createSiweMessage)
  const domain = new URL(API_BASE).host;
  const uri = API_BASE;
  const issuedAt = new Date().toISOString();
  const siweMessage = [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    '',
    'Sign in to CipherBox encrypted storage',
    '',
    `URI: ${uri}`,
    `Version: 1`,
    `Chain ID: 1`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join('\n');

  // 5. Sign SIWE message with wallet
  const signature = (await ethereum.request({
    method: 'personal_sign',
    params: [siweMessage, address],
  })) as string;

  // 6. Verify signature with CipherBox API
  const verifyResp = await fetch(`${API_BASE}/auth/identity/wallet`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: siweMessage, signature }),
  });
  if (!verifyResp.ok) {
    const body = await verifyResp.text().catch(() => '');
    throw new Error(`SIWE verification failed (${verifyResp.status}): ${body}`);
  }
  const { idToken: cipherboxJwt, userId } = await verifyResp.json();

  // 7. Core Kit loginWithJWT (same as Google/Email)
  return await loginWithCoreKit(cipherboxJwt, userId);
}

/**
 * Core Kit loginWithJWT + TSS key export + Rust handoff.
 *
 * Uses the exact same verifier name ('cipherbox-identity') and parameters
 * as the web app to ensure the same TSS key is derived for the same user.
 */
async function loginWithCoreKit(cipherboxJwt: string, userId: string): Promise<LoginResult> {
  if (!coreKit) throw new Error('Core Kit not initialized');

  // loginWithJWT with CipherBox identity verifier (matches web app exactly)
  console.log('[CoreKit] loginWithJWT starting...', {
    verifier: 'cipherbox-identity',
    verifierId: userId,
  });
  await coreKit.loginWithJWT({
    verifier: 'cipherbox-identity',
    verifierId: userId,
    idToken: cipherboxJwt,
  });
  console.log('[CoreKit] loginWithJWT completed, status:', coreKit.status);

  // Handle REQUIRED_SHARE status (MFA enabled, device factor missing)
  if (coreKit.status === COREKIT_STATUS.REQUIRED_SHARE) {
    console.log('[CoreKit] REQUIRED_SHARE -- MFA challenge needed');
    return { status: 'required_share' };
  }

  if (coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
    throw new Error(`Unexpected Core Kit status: ${coreKit.status}`);
  }

  // Commit changes (persist device factor to Web3Auth network)
  try {
    await coreKit.commitChanges();
    console.log('[CoreKit] commitChanges done');
  } catch (err) {
    console.error('[CoreKit] commitChanges failed:', err);
  }

  // Export TSS private key
  console.log('[CoreKit] Exporting TSS key...');
  const privateKeyHex = await coreKit._UNSAFE_exportTssKey();
  const privKeyHex = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
  console.log('[CoreKit] TSS key exported');

  // Pass credentials to Rust backend via Tauri IPC
  // The CipherBox JWT is sent as idToken -- backend verifies it with loginType 'corekit'
  await invoke('handle_auth_complete', {
    idToken: cipherboxJwt,
    privateKey: privKeyHex,
  });
  console.log('[CoreKit] Credentials passed to Rust backend');

  return { status: 'logged_in' };
}

/**
 * Logout from Core Kit and clear Rust-side state.
 *
 * Calls the Rust logout command first (clears Keychain, zeros keys),
 * then disconnects from Core Kit.
 */
export async function logout(): Promise<void> {
  // Clear Rust-side state (Keychain, memory keys)
  await invoke('logout');

  // Disconnect from Core Kit
  if (coreKit && coreKit.status === COREKIT_STATUS.LOGGED_IN) {
    try {
      await coreKit.logout();
    } catch (err) {
      // Best-effort -- don't fail logout if Core Kit cleanup fails
      console.warn('[CoreKit] Logout error (continuing):', err);
    }
  }

  console.log('[CoreKit] Logout complete');
}

/**
 * Load Google Identity Services (GIS) script dynamically and get a credential.
 *
 * Returns the Google JWT (credential) from the GIS prompt/popup flow.
 * Same pattern as web app's GoogleLoginButton component.
 */
function getGoogleCredential(): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!GOOGLE_CLIENT_ID) {
      reject(new Error('Google Client ID not configured (VITE_GOOGLE_CLIENT_ID)'));
      return;
    }

    // Safety timeout: if Google prompt doesn't resolve within 60s
    const timeoutId = setTimeout(() => {
      reject(new Error('Google authentication timed out'));
    }, 60000);

    const handleCredential = (response: { credential: string }) => {
      clearTimeout(timeoutId);
      resolve(response.credential);
    };

    // Check if GIS script is already loaded
    if (typeof google !== 'undefined' && google?.accounts?.id) {
      google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: handleCredential,
        auto_select: false,
      });
      google.accounts.id.prompt((notification) => {
        if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
          clearTimeout(timeoutId);
          reject(new Error('Google popup was blocked. Please allow popups for this app.'));
        }
      });
      return;
    }

    // Load GIS script dynamically
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.onload = () => {
      try {
        google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleCredential,
          auto_select: false,
        });
        google.accounts.id.prompt((notification) => {
          if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            clearTimeout(timeoutId);
            reject(new Error('Google popup was blocked. Please allow popups for this app.'));
          }
        });
      } catch {
        clearTimeout(timeoutId);
        reject(new Error('Failed to initialize Google authentication'));
      }
    };
    script.onerror = () => {
      clearTimeout(timeoutId);
      reject(new Error('Failed to load Google authentication'));
    };
    document.body.appendChild(script);
  });
}
