import { defineConfig, devices } from '@playwright/test';
import { config } from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// ESM compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables from .env file
config({ path: resolve(__dirname, '.env') });

// When BASE_URL points to an external environment (staging/prod), skip local webServer startup
const isExternalTarget =
  process.env.BASE_URL &&
  !process.env.BASE_URL.includes('localhost') &&
  !process.env.BASE_URL.includes('127.0.0.1');

export default defineConfig({
  testDir: './tests',

  // No global setup needed - tests handle their own authentication
  // (Removed globalSetup: './global-setup.ts')

  // Parallelize at the file level, not the test level: each spec file provisions
  // its own isolated wallet identity (unique privateKey -> unique backend userId),
  // so different files never share user/IPNS/DB state. Keep fullyParallel:false so
  // tests WITHIN a file still run serially — the describe.serial suites depend on
  // ordered, stateful steps. Local stays single-worker; CI fans out across files.
  // Ceiling is backend contention on the shared API/Kubo/Postgres stack, not
  // Web3Auth: 4 workers starved the write path (folder-create / IPFS add / IPNS
  // publish round-trips exceeded 30s on the 2-vCPU CI runner). 3 workers keeps
  // wall-clock well under the 20-min job cap without starving writes.
  fullyParallel: false,
  workers: process.env.CI ? 3 : 1,

  // Fail build on CI if tests marked as test.only
  forbidOnly: !!process.env.CI,

  // No retries - fix flakiness immediately (per CONTEXT.md)
  retries: 0,

  // Reporter for local and CI
  reporter: process.env.CI ? [['html', { open: 'never' }]] : 'list',

  use: {
    // Base URL for app under test (override with BASE_URL env var for staging)
    baseURL: process.env.BASE_URL || 'http://localhost:5173',

    // Capture artifacts on failure only
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',
  },

  // Projects - Chromium only (per CONTEXT.md)
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // No storage state - tests handle their own authentication in a single session
      },
    },
  ],

  // Web server configuration - start API, web app, and mock IPNS routing service
  // Skipped when BASE_URL points to an external environment (staging/prod)
  // Note: Commands run from the workspace root (two levels up from tests/web-e2e)
  ...(isExternalTarget
    ? {}
    : {
        webServer: [
          {
            // Mock IPNS routing service - must start first as API depends on it
            // Uses MOCK_IPNS_URL env var to allow external server (e.g., Docker)
            command: 'node tools/mock-ipns-routing/dist/index.js',
            url: process.env.MOCK_IPNS_URL || 'http://localhost:3001/health',
            reuseExistingServer: true, // Always reuse if available
            timeout: 30000,
            cwd: resolve(__dirname, '../..'),
            stdout: 'pipe',
            stderr: 'pipe',
          },
          {
            command: 'pnpm --filter @cipherbox/api dev',
            url: 'http://localhost:3000/health',
            reuseExistingServer: !process.env.CI,
            timeout: 120000,
            cwd: resolve(__dirname, '../..'),
            stdout: 'pipe',
            stderr: 'pipe',
          },
          {
            command: 'pnpm --filter @cipherbox/web dev',
            url: 'http://localhost:5173',
            reuseExistingServer: !process.env.CI,
            timeout: 120000,
            cwd: resolve(__dirname, '../..'),
          },
        ],
      }),
});
