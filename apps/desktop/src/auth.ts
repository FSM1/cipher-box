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
 *
 * MFA flow (REQUIRED_SHARE):
 *   When Core Kit returns REQUIRED_SHARE, the user needs a second factor.
 *   Two paths are supported:
 *   a) Recovery phrase: mnemonic -> mnemonicToKey -> inputFactorKey -> login complete
 *   b) Device approval: ephemeral keypair -> bulletin board request -> poll -> ECIES decrypt -> login complete
 */

import { invoke } from '@tauri-apps/api/core';
import {
  Web3AuthMPCCoreKit,
  WEB3AUTH_NETWORK,
  COREKIT_STATUS,
  mnemonicToKey,
  generateFactorKey,
  TssShareType,
  FactorKeyTypeShareDescription,
} from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import BN from 'bn.js';
import * as secp256k1 from '@noble/secp256k1';
import { wrapKey, unwrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';

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


let coreKit: Web3AuthMPCCoreKit | null = null;

// Module-level state for MFA flow
// Stored so MFA functions can complete auth after factor input
let lastCipherboxJwt: string | null = null;
let temporaryAccessToken: string | null = null;

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
 *
 * On REQUIRED_SHARE: stores the JWT and obtains a temporary access token
 * from the backend so the MFA UI can call device-approval endpoints.
 */
async function loginWithCoreKit(cipherboxJwt: string, userId: string): Promise<LoginResult> {
  if (!coreKit) throw new Error('Core Kit not initialized');

  // Store JWT for MFA completion later
  lastCipherboxJwt = cipherboxJwt;

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

    // Obtain temporary backend access token so the device can call
    // bulletin board API endpoints (device-approval/*).
    // Uses placeholder publicKey since Core Kit is in REQUIRED_SHARE
    // state and we can't export the TSS key yet.
    try {
      const tempResp = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idToken: cipherboxJwt,
          publicKey: `pending-core-kit-${userId}`,
          loginType: 'corekit',
        }),
      });
      if (tempResp.ok) {
        const { accessToken } = await tempResp.json();
        temporaryAccessToken = accessToken;
        console.log('[CoreKit] Temporary access token obtained for MFA flow');
      } else {
        console.warn('[CoreKit] Failed to get temporary token:', tempResp.status);
      }
    } catch (err) {
      console.warn('[CoreKit] Temporary token request failed:', err);
    }

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

  // Export TSS private key and complete auth
  await completeAuthHandoff(cipherboxJwt);

  return { status: 'logged_in' };
}

/**
 * Export TSS key and pass credentials to Rust backend via Tauri IPC.
 * Shared between normal login and MFA recovery completion.
 */
async function completeAuthHandoff(cipherboxJwt: string): Promise<void> {
  if (!coreKit) throw new Error('Core Kit not initialized');

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

  // Clear MFA state
  temporaryAccessToken = null;
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

// ---------------------------------------------------------------------------
// MFA Recovery and Device Approval
// ---------------------------------------------------------------------------

/**
 * Get or create a persistent device ID for this desktop.
 * Stored in localStorage keyed by 'cipherbox-desktop-device-id'.
 * Format: SHA-256 hex (64 chars) of a random 32-byte value.
 */
async function getDesktopDeviceId(): Promise<string> {
  const key = 'cipherbox-desktop-device-id';
  const stored = localStorage.getItem(key);
  if (stored && stored.length === 64) return stored;

  // Generate a random 32-byte value and SHA-256 hash it
  const random = crypto.getRandomValues(new Uint8Array(32));
  const hash = await crypto.subtle.digest('SHA-256', random);
  const deviceId = bytesToHex(new Uint8Array(hash));
  localStorage.setItem(key, deviceId);
  return deviceId;
}

/**
 * Get a human-readable device name for this desktop.
 * Uses navigator.userAgent to detect OS, prefixed with "CipherBox Desktop".
 */
function getDeviceName(): string {
  const ua = navigator.userAgent;
  if (/Macintosh|Mac OS X/i.test(ua)) return 'CipherBox Desktop on macOS';
  if (/Windows/i.test(ua)) return 'CipherBox Desktop on Windows';
  if (/Linux/i.test(ua)) return 'CipherBox Desktop on Linux';
  return 'CipherBox Desktop';
}

/**
 * Get the access token for API calls.
 * Uses temporary token (REQUIRED_SHARE state) or null.
 */
function getAccessToken(): string | null {
  return temporaryAccessToken;
}

/**
 * Recover from REQUIRED_SHARE using a 24-word recovery mnemonic.
 *
 * Flow:
 * 1. Convert mnemonic to factor key hex via mnemonicToKey
 * 2. Input factor key to Core Kit (transitions from REQUIRED_SHARE to LOGGED_IN)
 * 3. Create a device factor for this desktop so future logins skip MFA
 * 4. Export TSS key and complete auth (pass to Rust backend)
 *
 * @param mnemonic - 24-word BIP39 recovery phrase
 */
export async function inputRecoveryPhrase(mnemonic: string): Promise<void> {
  if (!coreKit) throw new Error('Core Kit not initialized');
  if (coreKit.status !== COREKIT_STATUS.REQUIRED_SHARE) {
    throw new Error('Not in REQUIRED_SHARE state');
  }

  // Convert mnemonic to factor key hex
  const factorKeyHex = mnemonicToKey(mnemonic.trim().toLowerCase());

  // Input the factor key to Core Kit
  await coreKit.inputFactorKey(new BN(factorKeyHex, 'hex'));

  // After successful input, Core Kit status should be LOGGED_IN
  // Cast needed: TS narrows status to REQUIRED_SHARE from earlier guard,
  // but inputFactorKey mutates the status to LOGGED_IN
  if ((coreKit.status as string) !== COREKIT_STATUS.LOGGED_IN) {
    throw new Error('Recovery failed: invalid recovery phrase');
  }
  console.log('[MFA] Recovery phrase accepted, status:', coreKit.status);

  // Create a device factor for this desktop so future logins don't need recovery
  const deviceId = await getDesktopDeviceId();
  const newDeviceFactor = generateFactorKey();
  await coreKit.createFactor({
    shareType: TssShareType.DEVICE,
    factorKey: newDeviceFactor.private,
    shareDescription: FactorKeyTypeShareDescription.DeviceShare,
    additionalMetadata: {
      deviceId,
      platform: 'macos',
      name: getDeviceName(),
    },
  });
  await coreKit.setDeviceFactor(newDeviceFactor.private);
  await coreKit.commitChanges();
  console.log('[MFA] Device factor created for future logins');

  // Export key and complete auth
  if (!lastCipherboxJwt) throw new Error('No stored JWT for auth completion');
  await completeAuthHandoff(lastCipherboxJwt);
}

/**
 * Create a device approval request on the CipherBox bulletin board.
 *
 * Generates an ephemeral secp256k1 keypair for ECIES key exchange.
 * The private key is stored in module scope and used to decrypt the
 * factor key when the request is approved.
 *
 * @returns requestId for polling, and stores ephemeral private key in module scope
 */
let ephemeralPrivateKey: Uint8Array | null = null;

export async function requestDeviceApproval(): Promise<string> {
  const token = getAccessToken();
  if (!token) throw new Error('No access token available');

  // Generate ephemeral secp256k1 keypair for ECIES key exchange
  const ephemeral = secp256k1.keygen();
  ephemeralPrivateKey = ephemeral.secretKey;
  const ephemeralPubKeyHex = bytesToHex(ephemeral.publicKey);

  const deviceId = await getDesktopDeviceId();

  const resp = await fetch(`${API_BASE}/device-approval/request`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      deviceId,
      deviceName: getDeviceName(),
      ephemeralPublicKey: ephemeralPubKeyHex,
    }),
  });
  if (!resp.ok) throw new Error('Failed to create approval request');
  const { requestId } = await resp.json();
  console.log('[MFA] Device approval request created:', requestId);
  return requestId;
}

/**
 * Poll the status of a device approval request.
 *
 * When approved, ECIES-decrypts the factor key with the ephemeral private key,
 * inputs it to Core Kit, creates a device factor, and completes auth.
 *
 * @returns Current status of the approval request
 */
export async function pollApprovalStatus(
  requestId: string
): Promise<'pending' | 'approved' | 'denied' | 'expired'> {
  const token = getAccessToken();
  if (!token) throw new Error('No access token available');

  const resp = await fetch(`${API_BASE}/device-approval/${requestId}/status`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  if (!resp.ok) throw new Error('Failed to check approval status');
  const { status, encryptedFactorKey } = await resp.json();

  if (status === 'approved' && encryptedFactorKey) {
    if (!ephemeralPrivateKey) throw new Error('Ephemeral private key not available');
    if (!coreKit) throw new Error('Core Kit not initialized');

    // ECIES-decrypt the factor key using the ephemeral private key
    const encrypted = hexToBytes(encryptedFactorKey);
    const factorKeyBytes = await unwrapKey(encrypted, ephemeralPrivateKey);
    const factorKeyHex = bytesToHex(factorKeyBytes);
    factorKeyBytes.fill(0); // Zero-fill after conversion

    // Clear ephemeral key from memory
    ephemeralPrivateKey.fill(0);
    ephemeralPrivateKey = null;

    // Input the factor key to complete Core Kit login
    await coreKit.inputFactorKey(new BN(factorKeyHex, 'hex'));
    console.log('[MFA] Factor key accepted, status:', coreKit.status);

    // Create device factor for future logins
    const deviceId = await getDesktopDeviceId();
    const newDeviceFactor = generateFactorKey();
    await coreKit.createFactor({
      shareType: TssShareType.DEVICE,
      factorKey: newDeviceFactor.private,
      shareDescription: FactorKeyTypeShareDescription.DeviceShare,
      additionalMetadata: {
        deviceId,
        platform: 'macos',
        name: getDeviceName(),
      },
    });
    await coreKit.setDeviceFactor(newDeviceFactor.private);
    await coreKit.commitChanges();
    console.log('[MFA] Device factor created after approval');

    // Export key and complete auth
    if (!lastCipherboxJwt) throw new Error('No stored JWT for auth completion');
    await completeAuthHandoff(lastCipherboxJwt);

    return 'approved';
  }

  return status;
}

/**
 * Cancel a pending device approval request.
 * Cleans up the ephemeral private key from memory.
 */
export async function cancelApprovalRequest(requestId: string): Promise<void> {
  const token = getAccessToken();
  if (!token) return;

  try {
    await fetch(`${API_BASE}/device-approval/${requestId}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    // Best-effort cleanup -- request may already be expired
  }

  // Clear ephemeral key
  if (ephemeralPrivateKey) {
    ephemeralPrivateKey.fill(0);
    ephemeralPrivateKey = null;
  }
}

/**
 * Approve a device approval request (API-complete stub).
 *
 * This function is fully implemented and tested, but has no UI trigger
 * in Phase 11.1. Users must approve devices from the web app.
 *
 * Phase 11.2 will add approval notification UI (tray icon notification +
 * approval dialog when desktop is the approving device).
 */
export async function approveDevice(
  requestId: string,
  ephemeralPublicKeyHex: string
): Promise<void> {
  if (!coreKit || coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
    throw new Error('Must be logged in to approve devices');
  }

  // Get current factor key from Core Kit
  const factorKeyResult = coreKit.getCurrentFactorKey();
  if (!factorKeyResult?.factorKey) {
    throw new Error('No active factor key available to share');
  }
  const factorKeyHex = factorKeyResult.factorKey.toString('hex').padStart(64, '0');
  const factorKeyBytes = hexToBytes(factorKeyHex);

  // ECIES-encrypt the factor key with the requester's ephemeral public key
  const ephemeralPubKey = hexToBytes(ephemeralPublicKeyHex);
  const encrypted = await wrapKey(factorKeyBytes, ephemeralPubKey);
  factorKeyBytes.fill(0); // Zero-fill after wrapping

  // Get device ID for tracking
  const deviceId = await getDesktopDeviceId();

  // Send approval response to the bulletin board
  const resp = await fetch(`${API_BASE}/device-approval/${requestId}/respond`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${temporaryAccessToken || ''}`,
    },
    body: JSON.stringify({
      action: 'approve',
      encryptedFactorKey: bytesToHex(encrypted),
      respondedByDeviceId: deviceId,
    }),
  });
  if (!resp.ok) throw new Error('Failed to approve device');
  console.log('[MFA] Device approved:', requestId);
}

// TODO (Phase 11.2): Add approval listener after auth success to poll for pending
// approval requests and show native notification when approval is needed.

/**
 * Get a Google credential (ID token) via OAuth2 implicit flow in a popup.
 *
 * GIS One Tap doesn't work in Tauri webview (no Google session, unregistered
 * origin). Instead, open a proper Google OAuth consent page in a popup window.
 * Tauri's on_new_window handler creates the popup with shared
 * WKWebViewConfiguration so window.opener.postMessage works for the callback.
 *
 * Requires `http://localhost:1420/google-callback.html` to be registered as
 * an authorized redirect URI in the Google Cloud Console.
 */
function getGoogleCredential(): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!GOOGLE_CLIENT_ID) {
      reject(new Error('Google Client ID not configured (VITE_GOOGLE_CLIENT_ID)'));
      return;
    }

    const nonce = crypto.randomUUID();
    const redirectUri = `${window.location.origin}/google-callback.html`;

    const params = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: 'id_token',
      scope: 'openid email profile',
      nonce,
      prompt: 'select_account',
    });

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;

    // Open Google OAuth in a popup — Tauri's on_new_window handler creates the webview
    const popup = window.open(authUrl, '_blank', 'width=500,height=700');

    const cleanup = () => {
      window.removeEventListener('message', handleMessage);
      clearInterval(checkClosed);
      clearTimeout(timeout);
    };

    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      if (event.data?.type !== 'google-auth-callback') return;

      cleanup();

      if (event.data.idToken) {
        resolve(event.data.idToken);
      } else {
        reject(new Error(event.data.error || 'Google sign-in failed'));
      }
    };
    window.addEventListener('message', handleMessage);

    // Detect if popup was closed without completing
    const checkClosed = setInterval(() => {
      if (popup && popup.closed) {
        cleanup();
        reject(new Error('Google sign-in was cancelled'));
      }
    }, 1000);

    // Timeout after 2 minutes
    const timeout = setTimeout(() => {
      cleanup();
      try { popup?.close(); } catch { /* cross-origin */ }
      reject(new Error('Google authentication timed out'));
    }, 120000);
  });
}
