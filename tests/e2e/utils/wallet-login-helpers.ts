import { type BrowserContext, type Page } from '@playwright/test';
import { installMockWallet } from '@johanneskares/wallet-mock';
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { http } from 'viem';

/**
 * Result of a wallet login attempt.
 * - `success`: Login completed, page redirected to /files.
 * - `requiredShare`: MFA is enabled and this device needs an additional share
 *   (DeviceWaitingScreen is shown).
 */
export type WalletLoginResult = { outcome: 'success' } | { outcome: 'requiredShare' };

/**
 * Generate a random viem account for MFA tests.
 *
 * Each test run uses a unique private key → unique wallet address →
 * unique userId in the backend → fresh DKG identity on Sapphire Devnet.
 * This ensures no pre-existing MFA state from previous runs.
 *
 * The account should be shared across all tests in a serial suite so
 * that the same Core Kit identity is used throughout.
 */
export function createTestAccount(): PrivateKeyAccount {
  return privateKeyToAccount(generatePrivateKey());
}

/**
 * Set up a mock wallet on a page (must be called BEFORE navigation).
 *
 * Creates an EIP-6963 mock provider that auto-announces itself.
 * wagmi's injected() connector auto-discovers it.
 *
 * @param page - Playwright page
 * @param account - viem account to use for signing (all contexts must share the same account)
 */
export async function setupMockWallet(page: Page, account: PrivateKeyAccount): Promise<void> {
  await installMockWallet({
    page,
    account,
    defaultChain: mainnet,
    transports: { [mainnet.id]: http() },
  });
}

/**
 * Create a new browser context with a mock wallet installed.
 *
 * Returns the context and its first page, both with the mock wallet
 * ready. The context must be closed by the caller.
 *
 * @param browser - Playwright browser instance
 * @param account - viem account to use (same account across all contexts)
 */
export async function createWalletContext(
  browser: { newContext: () => Promise<BrowserContext> },
  account: PrivateKeyAccount
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await setupMockWallet(page, account);
  return { context, page };
}

/**
 * Perform a full wallet login via the UI.
 *
 * Drives the real wallet -> SIWE -> Core Kit flow:
 * 1. Navigate to login page
 * 2. Wait for Core Kit init (wallet button becomes enabled)
 * 3. Click [WALLET] button -> connector list appears
 * 4. Select "Mock Wallet" connector
 * 5. Wait for either:
 *    - /files redirect (success, no MFA or device already known)
 *    - DeviceWaitingScreen (MFA enabled, new device needs share)
 *
 * The mock wallet auto-approves connect + signMessage, so the SIWE
 * flow proceeds without user interaction.
 *
 * @param page - Page with mock wallet already installed via setupMockWallet()
 * @param options.timeout - Max time to wait for login outcome (default: 60s)
 */
export async function loginViaWallet(
  page: Page,
  options: { timeout?: number } = {}
): Promise<WalletLoginResult> {
  const timeout = options.timeout ?? 60_000;

  // 1. Navigate to login page
  await page.goto('/');

  // 2. Wait for Core Kit to initialize (wallet button becomes enabled)
  const walletButton = page.locator('[data-testid="wallet-login-button"]');
  await walletButton.waitFor({ state: 'visible', timeout: 20_000 });
  // Poll until the button is enabled (Core Kit init can take several seconds)
  await page.waitForFunction(
    () => {
      const btn = document.querySelector(
        '[data-testid="wallet-login-button"]'
      ) as HTMLButtonElement;
      return btn && !btn.disabled;
    },
    { timeout: 20_000 }
  );

  // 3. Click wallet button to show connector list
  await walletButton.click();

  // 4. Select Mock Wallet from the connector list
  const connectorList = page.locator('.wallet-connector-list');
  await connectorList.waitFor({ state: 'visible', timeout: 5_000 });
  const mockWalletOption = page.locator('.wallet-connector-option', { hasText: 'Mock Wallet' });
  await mockWalletOption.click();

  // 5. Wait for outcome: either /files redirect or DeviceWaitingScreen
  const result = await Promise.race([
    page.waitForURL('**/files', { timeout }).then(() => ({ outcome: 'success' as const })),
    page
      .locator('[data-testid="device-waiting"]')
      .waitFor({ state: 'visible', timeout })
      .then(() => ({ outcome: 'requiredShare' as const })),
  ]);

  return result;
}
