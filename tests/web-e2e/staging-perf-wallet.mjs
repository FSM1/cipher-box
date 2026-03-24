import { chromium } from '@playwright/test';
import { installMockWallet } from '@johanneskares/wallet-mock';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { custom } from 'viem';

const STAGING_URL = 'https://app-staging.cipherbox.cc';
const API_HOST = 'api-staging.cipherbox.cc';

const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');

const localTransport = custom({
  async request({ method }) {
    switch (method) {
      case 'eth_chainId': return '0x1';
      case 'net_version': return '1';
      case 'eth_blockNumber': return '0x0';
      case 'eth_getBalance': return '0x0';
      default: throw new Error(`Mock transport: unhandled ${method}`);
    }
  },
});

async function run() {
  console.log('=== Staging Vault Login Path — E2E Performance Baseline ===');
  console.log(`Date: ${new Date().toISOString()}`);
  console.log(`Wallet address: ${account.address}`);
  console.log('');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Track API calls via Playwright's native request/response events
  const apiCalls = [];
  const pendingRequests = new Map();
  const t0 = Date.now();

  page.on('request', (req) => {
    if (req.url().includes(API_HOST)) {
      pendingRequests.set(req, { start: Date.now(), url: req.url(), method: req.method() });
    }
  });

  page.on('response', async (resp) => {
    const req = resp.request();
    const pending = pendingRequests.get(req);
    if (pending) {
      pendingRequests.delete(req);
      const elapsed = Date.now() - pending.start;
      const since = pending.start - t0;
      const path = new URL(pending.url).pathname;
      let size = resp.headers()['content-length'] || '?';
      apiCalls.push({ t: since, method: pending.method, status: resp.status(), ms: elapsed, url: path, size });
    }
  });

  // Install mock wallet BEFORE navigation
  await installMockWallet({
    page,
    account,
    defaultChain: mainnet,
    transports: { [mainnet.id]: localTransport },
  });

  // Navigate
  console.log('--- Phase 1: Page Load + Core Kit Init ---');
  const navStart = Date.now();
  await page.goto(STAGING_URL);
  await page.getByText('initializing...').first().waitFor({ state: 'hidden' });
  console.log(`  Page loaded: ${Date.now() - navStart}ms`);

  const walletButton = page.locator('[data-testid="wallet-login-button"]');
  await walletButton.waitFor({ state: 'visible', timeout: 20_000 });
  await page.waitForFunction(
    () => {
      const btn = document.querySelector('[data-testid="wallet-login-button"]');
      return btn && !btn.disabled;
    },
    { timeout: 20_000 }
  );
  console.log(`  Core Kit ready: ${Date.now() - navStart}ms`);
  console.log('');

  // Login
  console.log('--- Phase 2: Wallet Login (SIWE + Core Kit + Vault Init) ---');
  const loginStart = Date.now();
  await walletButton.click();

  const connectorList = page.locator('.wallet-connector-list');
  await connectorList.waitFor({ state: 'visible', timeout: 5_000 });
  const mockWalletOption = page.locator('.wallet-connector-option', { hasText: 'Mock Wallet' });
  await mockWalletOption.click();
  console.log(`  Wallet selected: ${Date.now() - loginStart}ms`);

  try {
    const result = await Promise.race([
      page.waitForURL('**/files', { timeout: 60_000 }).then(() => 'success'),
      page.locator('[data-testid="device-waiting"]')
        .waitFor({ state: 'visible', timeout: 60_000 })
        .then(() => 'requiredShare'),
    ]);
    console.log(`  Login outcome: ${result} (${Date.now() - loginStart}ms)`);

    if (result === 'success') {
      await Promise.race([
        page.locator('.file-list[role="grid"]').waitFor({ state: 'visible', timeout: 30_000 }),
        page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30_000 }),
      ]);
      console.log(`  Vault ready (files visible): ${Date.now() - loginStart}ms`);
    }
  } catch (e) {
    console.log(`  Login failed: ${e.message}`);
    await page.screenshot({ path: '/tmp/staging-perf-fail.png' });
  }

  // Print API waterfall
  console.log('');
  console.log('--- API Call Waterfall ---');
  if (apiCalls.length > 0) {
    console.log(`${'T(ms)'.padStart(7)} | ${'Method'.padEnd(6)} | ${'Status'.padEnd(6)} | ${'Dur'.padEnd(6)} | Path`);
    console.log(`${''.padStart(7, '-')} | ${''.padEnd(6, '-')} | ${''.padEnd(6, '-')} | ${''.padEnd(6, '-')} | ----`);
    for (const c of apiCalls) {
      console.log(
        `${String(c.t).padStart(7)} | ${c.method.padEnd(6)} | ${String(c.status).padEnd(6)} | ${(c.ms + 'ms').padEnd(6)} | ${c.url}`
      );
    }
  } else {
    console.log('(no API calls captured)');
  }

  // Summary
  printSummary(apiCalls);

  // =====================================================================
  // Phase 3: Session Restore (page reload — Core Kit re-init)
  // Core Kit must re-initialize on reload (tKey shares not persisted
  // in headless Playwright). This measures the "return to app" path.
  // =====================================================================
  console.log('');
  console.log('==========================================================');
  console.log('--- Phase 3: Session Restore (page reload) ---');
  console.log('  Note: Core Kit re-initializes on reload in headless mode.');

  // Clear tracking for this phase
  const restoreCalls = [];
  const restorePending = new Map();
  const rt0 = Date.now();

  // Swap listeners for this phase
  page.removeAllListeners('request');
  page.removeAllListeners('response');

  page.on('request', (req) => {
    if (req.url().includes(API_HOST)) {
      restorePending.set(req, { start: Date.now(), url: req.url(), method: req.method() });
    }
  });

  page.on('response', async (resp) => {
    const req = resp.request();
    const pending = restorePending.get(req);
    if (pending) {
      restorePending.delete(req);
      const elapsed = Date.now() - pending.start;
      const since = pending.start - rt0;
      const path = new URL(pending.url).pathname;
      restoreCalls.push({ t: since, method: pending.method, status: resp.status(), ms: elapsed, url: path });
    }
  });

  const restoreStart = Date.now();
  await page.reload({ waitUntil: 'domcontentloaded' });

  // Wait for app to restore session and show files
  try {
    await Promise.race([
      page.locator('.file-list[role="grid"]').waitFor({ state: 'visible', timeout: 60_000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 60_000 }),
    ]);
    console.log(`  Session restored (files visible): ${Date.now() - restoreStart}ms`);
  } catch (e) {
    console.log(`  Session restore failed: ${e.message}`);
    // Maybe it went back to login
    const currentUrl = page.url();
    console.log(`  Current URL: ${currentUrl}`);
    await page.screenshot({ path: '/tmp/staging-restore-fail.png' });
  }

  // Print restore waterfall
  console.log('');
  console.log('--- Session Restore API Waterfall ---');
  printWaterfall(restoreCalls);
  console.log('');
  printSummary(restoreCalls);

  await browser.close();
  console.log('');
  console.log('=== Done ===');
}

function printWaterfall(calls) {
  if (calls.length > 0) {
    console.log(`${'T(ms)'.padStart(7)} | ${'Method'.padEnd(6)} | ${'Status'.padEnd(6)} | ${'Dur'.padEnd(6)} | Path`);
    console.log(`${''.padStart(7, '-')} | ${''.padEnd(6, '-')} | ${''.padEnd(6, '-')} | ${''.padEnd(6, '-')} | ----`);
    for (const c of calls) {
      console.log(
        `${String(c.t).padStart(7)} | ${c.method.padEnd(6)} | ${String(c.status).padEnd(6)} | ${(c.ms + 'ms').padEnd(6)} | ${c.url}`
      );
    }
  } else {
    console.log('(no API calls captured)');
  }
}

function printSummary(calls) {
  console.log('--- Summary ---');
  const authCalls = calls.filter(c => c.url.includes('/auth'));
  const vaultCalls = calls.filter(c => c.url.includes('/vault'));
  const ipnsCalls = calls.filter(c => c.url.includes('/ipns'));
  const ipfsCalls = calls.filter(c => c.url.includes('/ipfs'));
  console.log(`Auth calls: ${authCalls.length} (total: ${authCalls.reduce((s, c) => s + c.ms, 0)}ms)`);
  console.log(`Vault calls: ${vaultCalls.length} (total: ${vaultCalls.reduce((s, c) => s + c.ms, 0)}ms)`);
  console.log(`IPNS calls: ${ipnsCalls.length} (total: ${ipnsCalls.reduce((s, c) => s + c.ms, 0)}ms)`);
  console.log(`IPFS calls: ${ipfsCalls.length} (total: ${ipfsCalls.reduce((s, c) => s + c.ms, 0)}ms)`);
}

run().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
