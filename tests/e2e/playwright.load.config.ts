import { defineConfig, devices } from '@playwright/test';
import { config } from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

config({ path: resolve(__dirname, '.env') });

/**
 * Playwright config for load testing against staging.
 *
 * Differences from the default config:
 * - Points at the deployed staging app (no local webServer)
 * - Single worker (concurrency is managed inside the test via multiple browser contexts)
 * - Longer timeouts for SIWE + Core Kit auth flow
 * - No retries
 *
 * Usage:
 *   cd tests/e2e
 *   pnpm exec playwright test tests/load-test.spec.ts --config=playwright.load.config.ts
 *
 * Env vars:
 *   LOAD_TEST_CLIENTS=5   Number of concurrent browser contexts (default: 3)
 *   LOAD_TEST_ROUNDS=3    Operation rounds per client (default: 2)
 */
export default defineConfig({
  testDir: './tests',
  testMatch: 'load-test.spec.ts',

  // Single worker — concurrency is within the test (multiple browser contexts)
  fullyParallel: false,
  workers: 1,

  forbidOnly: true,
  retries: 0,

  // 10 minute global timeout (load tests are long)
  timeout: 600_000,

  reporter: 'list',

  use: {
    // Point at the deployed staging app
    baseURL: 'https://app-staging.cipherbox.cc',

    // No artifacts for load tests (noise)
    screenshot: 'off',
    video: 'off',
    trace: 'off',

    // Longer action timeout for staging latency
    actionTimeout: 30_000,
  },

  projects: [
    {
      name: 'chromium-load',
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],

  // No webServer — we're hitting the deployed staging app directly
});
