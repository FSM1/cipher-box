// The web e2e smoke slice (blueprint/testing.md "E2E"). Both projects run
// against the production static build, served from a built directory — the
// artifact that ships is the artifact tested. `e2e` drives the build carrying
// the introspection hook; `release` drives the same build without the flag.
//
// `retries: 0` is policy, not tuning: a flaky test is a defect.
import { defineConfig, devices } from '@playwright/test';

const E2E_PORT = 4173;
const RELEASE_PORT = 4174;

const isCi = Boolean(process.env.CI);

const url = (port: number) => `http://localhost:${port}`;

/**
 * Serves one already-built bundle with the SPA fallback the routes need.
 * `reuse` is off for the release bundle even locally: reusing whatever already
 * answers on that port would make the hook-absence assertion meaningless.
 */
const preview = (outDir: string, port: number, reuse = false) => ({
  command: `pnpm --filter @cipherbox/web exec vite preview --outDir ${outDir} --port ${port} --strictPort`,
  url: url(port),
  reuseExistingServer: reuse && !isCi,
  timeout: 60_000,
  stdout: 'pipe' as const,
  stderr: 'pipe' as const,
});

export default defineConfig({
  testDir: './tests',
  // Every test cold-starts its own vault from a fresh login secret, so nothing
  // is shared to serialize around.
  fullyParallel: true,
  forbidOnly: isCi,
  retries: 0,
  timeout: 120_000,
  reporter: isCi ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    // Chrome's own headless, not Playwright's default `chrome-headless-shell`:
    // the shell segfaults on a page that registers a Service Worker, killing the
    // browser under whichever assertion is in flight.
    channel: 'chromium',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'e2e',
      testMatch: '**/smoke.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: url(E2E_PORT) },
    },
    {
      name: 'release',
      testMatch: '**/release-bundle.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: url(RELEASE_PORT) },
    },
  ],
  webServer: [preview('dist', E2E_PORT, true), preview('dist-release', RELEASE_PORT)],
});
