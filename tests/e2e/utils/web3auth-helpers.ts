import { Page } from '@playwright/test';
import {
  initializeVault,
  encryptVaultKeys,
  decryptVaultKeys,
  deriveIpnsName,
  hexToBytes,
  bytesToHex,
} from '@cipherbox/crypto';
import * as ed from '@noble/ed25519';

/**
 * Test credentials from environment variables.
 * These are loaded from .env locally or GitHub Secrets in CI.
 *
 * With Core Kit, the E2E flow uses CipherBox's own login UI:
 * 1. Enter email in CipherBox email input
 * 2. Backend sends OTP (static OTP in test mode)
 * 3. Enter OTP code
 * 4. CipherBox JWT -> Core Kit loginWithJWT -> backend auth -> vault init
 */
export const TEST_CREDENTIALS = {
  email: process.env.WEB3AUTH_TEST_EMAIL || '',
  otp: process.env.WEB3AUTH_TEST_OTP || '',
};

/**
 * Cached auth state from test-login endpoint.
 * Used to re-inject state after page reload (since test-login bypasses
 * Core Kit, there's no persistent session to restore from).
 */
let cachedTestAuthState: {
  accessToken: string;
  email: string;
  publicKeyArr: number[];
  privateKeyArr: number[];
  rootFolderKeyArr: number[];
  rootIpnsPublicKeyArr: number[];
  rootIpnsPrivateKeyArr: number[];
  rootIpnsName: string;
  vaultId: string;
} | null = null;

/**
 * Performs email login through CipherBox's custom login UI.
 *
 * When TEST_LOGIN_SECRET is set, uses the /auth/test-login endpoint to bypass
 * Core Kit entirely. This decouples E2E tests from Web3Auth infrastructure.
 *
 * Otherwise falls back to the full Core Kit flow through CipherBox's login UI.
 *
 * @param page - Playwright page instance
 * @param email - Email address for login
 * @param otp - Optional OTP code (defaults to TEST_CREDENTIALS.otp)
 */
export async function loginViaEmail(page: Page, email: string, otp?: string): Promise<void> {
  // Use test-login endpoint when available (bypasses Core Kit completely)
  if (process.env.TEST_LOGIN_SECRET) {
    await loginViaTestEndpoint(page, email);
    return;
  }

  const otpCode = otp || TEST_CREDENTIALS.otp;

  // Navigate to login page
  await page.goto('/');

  // Step 1: Enter email in CipherBox's own email input
  const emailInput = page.locator('[data-testid="email-input"]');
  await emailInput.waitFor({ state: 'visible', timeout: 15000 });
  await emailInput.fill(email);

  // Step 2: Click [SEND OTP] button
  const sendOtpButton = page.locator('[data-testid="send-otp-button"]');
  await sendOtpButton.click();

  // Step 3: Wait for OTP input to appear (backend sends OTP, form transitions)
  const otpInput = page.locator('[data-testid="otp-input"]');
  await otpInput.waitFor({ state: 'visible', timeout: 15000 });

  // Step 4: Enter the test OTP code
  await otpInput.fill(otpCode);

  // Step 5: Click [VERIFY] button
  const verifyButton = page.locator('[data-testid="verify-button"]');
  await verifyButton.click();

  // Step 6: Wait for login to complete and redirect to files page
  // Core Kit loginWithJWT + backend auth + vault init can take time
  await page.waitForURL('**/files', { timeout: 60000 });
}

/**
 * Test-login endpoint flow that bypasses Core Kit entirely.
 *
 * 1. Calls POST /auth/test-login → tokens + deterministic secp256k1 keypair
 * 2. Handles vault init/load using @cipherbox/crypto in Node.js
 * 3. Injects all state into Zustand stores via page.evaluate
 * 4. Navigates to /files
 *
 * This is completely independent of Web3Auth infrastructure.
 */
async function loginViaTestEndpoint(page: Page, email: string): Promise<void> {
  const apiBase = process.env.API_BASE_URL || 'http://localhost:3000';
  const secret = process.env.TEST_LOGIN_SECRET!;

  // 1. Authenticate via test-login endpoint
  const loginResponse = await page.request.post(`${apiBase}/auth/test-login`, {
    data: { email, secret },
  });

  if (!loginResponse.ok()) {
    const body = await loginResponse.text();
    throw new Error(`Test login failed (${loginResponse.status()}): ${body}`);
  }

  const { accessToken, refreshToken, publicKeyHex, privateKeyHex } = await loginResponse.json();
  const publicKey = hexToBytes(publicKeyHex);
  const privateKey = hexToBytes(privateKeyHex);

  // 2. Handle vault: load existing or initialize new
  const vaultResponse = await page.request.get(`${apiBase}/vault`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  let vaultId: string;
  let rootFolderKey: Uint8Array;
  let rootIpnsPrivateKey: Uint8Array;
  let rootIpnsName: string;

  if (vaultResponse.ok()) {
    // Existing vault — decrypt keys
    const vault = await vaultResponse.json();
    vaultId = vault.id;
    rootIpnsName = vault.rootIpnsName;

    const decrypted = await decryptVaultKeys(
      {
        encryptedRootFolderKey: hexToBytes(vault.encryptedRootFolderKey),
        encryptedIpnsPrivateKey: hexToBytes(vault.encryptedRootIpnsPrivateKey),
      },
      privateKey
    );

    rootFolderKey = decrypted.rootFolderKey;
    rootIpnsPrivateKey = decrypted.rootIpnsKeypair.privateKey;
  } else {
    // New user — initialize vault
    const newVault = await initializeVault(privateKey);
    const encrypted = await encryptVaultKeys(newVault, publicKey);
    rootIpnsName = await deriveIpnsName(newVault.rootIpnsKeypair.publicKey);

    const initResponse = await page.request.post(`${apiBase}/vault/init`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      data: {
        ownerPublicKey: publicKeyHex,
        encryptedRootFolderKey: bytesToHex(encrypted.encryptedRootFolderKey),
        encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
        rootIpnsName,
      },
    });

    if (!initResponse.ok()) {
      const body = await initResponse.text();
      throw new Error(`Vault init failed (${initResponse.status()}): ${body}`);
    }

    const initResult = await initResponse.json();
    vaultId = initResult.id;
    rootFolderKey = newVault.rootFolderKey;
    rootIpnsPrivateKey = newVault.rootIpnsKeypair.privateKey;
  }

  // Derive IPNS public key from private key (deterministic Ed25519 derivation)
  const rootIpnsPublicKey = await ed.getPublicKeyAsync(rootIpnsPrivateKey);

  // Cache state for re-injection after page reloads
  cachedTestAuthState = {
    accessToken,
    email,
    publicKeyArr: Array.from(publicKey),
    privateKeyArr: Array.from(privateKey),
    rootFolderKeyArr: Array.from(rootFolderKey),
    rootIpnsPublicKeyArr: Array.from(rootIpnsPublicKey),
    rootIpnsPrivateKeyArr: Array.from(rootIpnsPrivateKey),
    rootIpnsName,
    vaultId,
  };

  // 2.5. Set refresh token cookie in the browser context for session persistence
  const url = new URL(apiBase);
  await page.context().addCookies([
    {
      name: 'refresh_token',
      value: refreshToken,
      domain: url.hostname,
      path: '/auth',
      httpOnly: true,
      secure: false, // dev mode
      sameSite: 'Lax',
    },
  ]);

  // 3. Navigate to app so we can inject state into Zustand stores
  await page.goto('/');

  await injectTestAuthState(page);

  // 5. Navigate to files page via hash router (no full reload — preserves Zustand state)
  await page.evaluate(() => {
    window.location.hash = '#/files';
  });
  await page.waitForURL('**/files', { timeout: 30000 });
}

/**
 * Inject cached test auth state into Zustand stores.
 * Used both during initial login and after page reloads.
 */
async function injectTestAuthState(page: Page): Promise<void> {
  if (!cachedTestAuthState) {
    throw new Error('No cached test auth state — call loginViaEmail first');
  }

  // Wait for the app to load and expose stores (dev mode only)
  await page.waitForFunction(() => !!(window as Record<string, unknown>).__ZUSTAND_STORES, {
    timeout: 15000,
  });

  // Inject auth + vault state into Zustand stores
  // Arrays are used because Uint8Array can't be serialized across page.evaluate boundary
  await page.evaluate((data) => {
    const stores = (window as Record<string, unknown>).__ZUSTAND_STORES as {
      auth: { setState: (s: Record<string, unknown>) => void };
      vault: { getState: () => { setVaultKeys: (k: Record<string, unknown>) => void } };
    };

    stores.auth.setState({
      accessToken: data.accessToken,
      isAuthenticated: true,
      lastAuthMethod: 'email_passwordless',
      userEmail: data.email,
      derivedKeypair: {
        publicKey: new Uint8Array(data.publicKeyArr),
        privateKey: new Uint8Array(data.privateKeyArr),
      },
    });

    stores.vault.getState().setVaultKeys({
      rootFolderKey: new Uint8Array(data.rootFolderKeyArr),
      rootIpnsKeypair: {
        publicKey: new Uint8Array(data.rootIpnsPublicKeyArr),
        privateKey: new Uint8Array(data.rootIpnsPrivateKeyArr),
      },
      rootIpnsName: data.rootIpnsName,
      vaultId: data.vaultId,
    });
  }, cachedTestAuthState);
}

/**
 * Re-inject test auth state after a page reload.
 * Since test-login bypasses Core Kit, there's no persistent session —
 * this function restores Zustand stores from the cached first login,
 * refreshes the access token via the HTTP-only cookie, then navigates
 * to /files.
 *
 * Call this after page.reload() in tests that use the test-login flow.
 * For tests using the real Core Kit flow, this is a no-op (Core Kit
 * auto-restores its session).
 */
export async function reinjectTestAuthAfterReload(page: Page): Promise<void> {
  // If not using test-login, Core Kit handles session restore
  if (!process.env.TEST_LOGIN_SECRET || !cachedTestAuthState) return;

  // Try to refresh the access token via the cookie
  const apiBase = process.env.API_BASE_URL || 'http://localhost:3000';
  const refreshResponse = await page.request.post(`${apiBase}/auth/refresh`);

  if (refreshResponse.ok()) {
    const { accessToken, email } = await refreshResponse.json();
    cachedTestAuthState.accessToken = accessToken;
    if (email) cachedTestAuthState.email = email;
  }

  await injectTestAuthState(page);

  // Navigate to files via hash router
  await page.evaluate(() => {
    window.location.hash = '#/files';
  });
  await page.waitForURL('**/files', { timeout: 30000 });
}

/**
 * Gets the current storage state (cookies and localStorage).
 * Useful for saving authenticated session state.
 */
export async function getStorageState(page: Page): Promise<object> {
  return await page.context().storageState();
}

/**
 * Waits for the user to be authenticated by checking for auth indicators.
 * This is useful after manual login or when loading storage state.
 */
export async function waitForAuthentication(page: Page): Promise<void> {
  // Wait for user menu to appear (indicator of authenticated state)
  // Phase 6.3: Logout moved to UserMenu dropdown
  await page.waitForSelector('[data-testid="user-menu"]', { timeout: 15000 });
}
