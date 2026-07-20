import { defineConfig, devices } from '@playwright/test';

/**
 * The `packages/client` browser suite (blueprint/testing.md law 1): the engine
 * seam conformance kits run against the real browser seam implementations in a
 * real browser, over real IndexedDB and OPFS. A Vite dev server hosts the
 * harness and mocks the `/routing/v1` and plain-HTTP surfaces the seams touch.
 * Wired as a merge-blocking CI job in `.github/workflows/ci.yml`.
 */
const isCi = Boolean(process.env.CI);

export default defineConfig({
  testDir: './test/browser',
  testMatch: '**/*.spec.ts',
  fullyParallel: false,
  forbidOnly: isCi,
  retries: 0,
  workers: 1,
  timeout: 60_000,
  reporter: isCi ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://localhost:5178',
    headless: true,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm exec vite --config test/browser/vite.config.ts',
    url: 'http://localhost:5178',
    reuseExistingServer: !isCi,
    timeout: 120_000,
  },
});
