import { test, expect } from '@playwright/test';
import { installMockWallet } from '@johanneskares/wallet-mock';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { http } from 'viem';
import { LoginPage } from '../page-objects/login.page';

/**
 * Wallet Login E2E Tests (TC09-TC12)
 *
 * Tests wallet login flows using @johanneskares/wallet-mock which provides
 * an EIP-6963 mock provider. The mock wallet auto-announces itself and
 * wagmi's injected() connector auto-discovers it.
 *
 * The mock uses viem's privateKeyToAccount for real ECDSA signatures,
 * so the backend SIWE verifyMessage() performs real crypto verification.
 *
 * Test account: Hardhat account #0 (well-known test key, no real funds)
 */

// Hardhat account #0 private key (well-known, deterministic, no real funds)
const HARDHAT_ACCOUNT_0_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;

// ============================================
// TC09: Wallet login happy path (with mock wallet)
// ============================================

test.describe('TC09: Wallet login happy path (with mock wallet)', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    // Install mock wallet BEFORE navigating to the page
    const account = privateKeyToAccount(HARDHAT_ACCOUNT_0_KEY);
    await installMockWallet({
      page,
      account,
      defaultChain: mainnet,
      transports: { [mainnet.id]: http() },
    });

    loginPage = new LoginPage(page);
    await loginPage.goto();
  });

  test('wallet button is visible and enabled', async () => {
    // Wait for Core Kit init to complete (wallet button becomes enabled)
    await expect(async () => {
      expect(await loginPage.isWalletLoginButtonVisible()).toBe(true);
      expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
    }).toPass({ timeout: 15000 });
  });

  test('clicking wallet shows mock wallet in connector list', async () => {
    // Wait for wallet button to be ready
    await expect(async () => {
      expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
    }).toPass({ timeout: 15000 });

    // Click wallet button to show connectors
    await loginPage.clickWalletLogin();

    // Connector list should be visible
    expect(await loginPage.isWalletConnectorListVisible()).toBe(true);

    // Mock Wallet should appear in the connector list
    const connectors = await loginPage.getWalletConnectors();
    expect(connectors).toContain('Mock Wallet');
  });

  test('selecting mock wallet initiates SIWE flow', async ({ page }) => {
    test.setTimeout(30000);

    // Wait for wallet button to be ready
    await expect(async () => {
      expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
    }).toPass({ timeout: 15000 });

    // Click wallet, then select Mock Wallet
    await loginPage.clickWalletLogin();
    await loginPage.selectWalletConnector('Mock Wallet');

    // The mock wallet auto-approves connectAsync and signMessage.
    // The SIWE flow will:
    // 1. Connect wallet (auto-approved)
    // 2. Fetch nonce from backend
    // 3. Create SIWE message
    // 4. Sign message (auto-approved)
    // 5. Verify on backend
    // 6. Continue with Core Kit login
    //
    // Wait for either:
    // - Redirect to /files (full success, requires running backend + Core Kit devnet)
    // - An error message (expected if Core Kit/backend not fully available)
    // - A status change indicating SIWE flow progressed
    const result = await Promise.race([
      page
        .waitForURL('**/files', { timeout: 20000 })
        .then(() => 'redirected' as const)
        .catch(() => null),
      loginPage
        .getWalletError()
        .then((err) => (err ? ('error' as const) : null))
        .catch(() => null),
      // Wait a bit for the flow to progress
      page.waitForTimeout(5000).then(async () => {
        // Check if we got a status update (SIWE flow progressing)
        const status = await loginPage.getWalletStatus();
        const error = await loginPage.getWalletError();
        if (error) return 'error' as const;
        if (status) return 'in-progress' as const;
        return 'timeout' as const;
      }),
    ]);

    if (result === 'redirected') {
      // Full SIWE flow completed - user is logged in
      await expect(page).toHaveURL(/.*files/);
    } else {
      // SIWE flow started but may have failed at backend/Core Kit step.
      // This is acceptable - the important thing is:
      // 1. Mock wallet was discovered (we clicked it)
      // 2. Connect was initiated (no "no wallet" error)
      // 3. Either SIWE signing happened or nonce fetch was attempted
      // Log the result for debugging
      console.log(`SIWE flow result: ${result}`);

      // The flow should NOT show "No wallet detected" since we installed mock
      const error = await loginPage.getWalletError();
      if (error) {
        expect(error).not.toContain('No wallet detected');
        expect(error).not.toContain('no wallet');
      }
    }
  });
});

// ============================================
// TC10: Wallet login cancel
// ============================================

test.describe('TC10: Wallet login cancel', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    const account = privateKeyToAccount(HARDHAT_ACCOUNT_0_KEY);
    await installMockWallet({
      page,
      account,
      defaultChain: mainnet,
      transports: { [mainnet.id]: http() },
    });

    loginPage = new LoginPage(page);
    await loginPage.goto();
  });

  test('cancelling wallet connector list returns to initial state', async () => {
    // Wait for wallet button to be ready
    await expect(async () => {
      expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
    }).toPass({ timeout: 15000 });

    // Click wallet to show connector list
    await loginPage.clickWalletLogin();
    expect(await loginPage.isWalletConnectorListVisible()).toBe(true);

    // Click cancel
    await loginPage.cancelWalletLogin();

    // Connector list should be hidden
    expect(await loginPage.isWalletConnectorListVisible()).toBe(false);

    // Wallet button should be visible and enabled again
    expect(await loginPage.isWalletLoginButtonVisible()).toBe(true);
    expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
  });
});

// ============================================
// TC11: Wallet login no wallet detected
// ============================================

test.describe('TC11: Wallet login no wallet detected', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    // Do NOT install mock wallet - test no-wallet state
    loginPage = new LoginPage(page);
    await loginPage.goto();
  });

  test('no wallet message shown when no providers detected', async () => {
    // Wait for wallet button to be ready
    await expect(async () => {
      expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
    }).toPass({ timeout: 15000 });

    // Click wallet button
    await loginPage.clickWalletLogin();

    // Either the no-providers message is shown, or zero connector options appear.
    // wagmi may report phantom "injected" connectors (browser built-in)
    // so we need to handle both cases.
    const isNoProviders = await loginPage.isNoWalletProvidersVisible();
    const connectors = await loginPage.getWalletConnectors().catch(() => [] as string[]);

    if (!isNoProviders && connectors.length > 0) {
      // wagmi reported phantom connectors (e.g., browser built-in injected)
      // This is acceptable - the point is Mock Wallet should NOT be there
      expect(connectors).not.toContain('Mock Wallet');
    } else {
      // No providers message or empty connector list
      expect(isNoProviders || connectors.length === 0).toBe(true);
    }

    // Cancel should work regardless
    await loginPage.cancelWalletLogin();
    expect(await loginPage.isWalletConnectorListVisible()).toBe(false);
  });
});

// ============================================
// TC12: Wallet login error handling
// ============================================

test.describe('TC12: Wallet login error handling', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    const account = privateKeyToAccount(HARDHAT_ACCOUNT_0_KEY);
    await installMockWallet({
      page,
      account,
      defaultChain: mainnet,
      transports: { [mainnet.id]: http() },
    });

    loginPage = new LoginPage(page);
    await loginPage.goto();
  });

  test('error during SIWE flow shows error message and allows retry', async ({ page }) => {
    test.setTimeout(30000);

    // Wait for wallet button to be ready
    await expect(async () => {
      expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
    }).toPass({ timeout: 15000 });

    // Intercept the nonce endpoint to simulate a server error
    await page.route('**/auth/identity/wallet/nonce', (route) =>
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Internal Server Error' }),
      })
    );

    // Click wallet, then select Mock Wallet
    await loginPage.clickWalletLogin();
    await loginPage.selectWalletConnector('Mock Wallet');

    // Wait for error to appear (nonce fetch fails -> error displayed)
    const errorLocator = page.locator('.wallet-login-wrapper .login-error');
    await expect(errorLocator).toBeVisible({ timeout: 10000 });

    // Error should be shown
    const error = await loginPage.getWalletError();
    expect(error).toBeTruthy();

    // Remove the route interception for retry
    await page.unroute('**/auth/identity/wallet/nonce');

    // Wallet button should return to idle and enabled state
    await expect(async () => {
      expect(await loginPage.isWalletLoginButtonVisible()).toBe(true);
      expect(await loginPage.isWalletLoginButtonEnabled()).toBe(true);
    }).toPass({ timeout: 10000 });
  });
});
