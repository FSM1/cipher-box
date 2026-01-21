import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',

  // Run tests sequentially initially (per CONTEXT.md)
  fullyParallel: false,
  workers: 1,

  // Fail build on CI if tests marked as test.only
  forbidOnly: !!process.env.CI,

  // No retries - fix flakiness immediately (per CONTEXT.md)
  retries: 0,

  // Reporter for local and CI
  reporter: process.env.CI ? [['html', { open: 'never' }]] : 'list',

  use: {
    // Base URL for app under test
    baseURL: 'http://localhost:5173',

    // Capture artifacts on failure only
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',
  },

  // Projects - Chromium only (per CONTEXT.md)
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Web server configuration - automatically start web app
  webServer: {
    command: 'pnpm --filter @cipherbox/web dev',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
