import { defineConfig, devices } from '@playwright/test';
import { config } from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// ESM compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables from .env file
config({ path: resolve(__dirname, '.env') });

export default defineConfig({
  testDir: './tests',

  // No global setup needed - tests handle their own authentication
  // (Removed globalSetup: './global-setup.ts')

  // Run tests sequentially (single session approach)
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
      use: {
        ...devices['Desktop Chrome'],
        // No storage state - tests handle their own authentication in a single session
      },
    },
  ],

  // Web server configuration - start API, web app, and mock IPNS routing service
  // Note: Commands run from the workspace root (two levels up from tests/e2e)
  webServer: [
    {
      // Mock IPNS routing service - must start first as API depends on it
      command: 'node tools/mock-ipns-routing/dist/index.js',
      url: 'http://localhost:3001/health',
      reuseExistingServer: !process.env.CI,
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
});
