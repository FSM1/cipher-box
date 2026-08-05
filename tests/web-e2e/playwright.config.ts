import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

/**
 * The web e2e smoke slice (blueprint/testing.md "E2E"). Both projects run
 * against the **production static build**, served from `dist/` — the artifact
 * that ships is the artifact tested. `e2e` drives the build that carries the
 * introspection hook; `release` drives the same build without the flag and
 * asserts the hook is not in it.
 *
 * `retries: 0` is policy, not tuning: a flaky test is a defect. The suite polls
 * the introspection hook for a settled vault and never sleeps.
 */
const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

const E2E_URL = 'http://localhost:4173';
const RELEASE_URL = 'http://localhost:4174';

const isCi = Boolean(process.env.CI);

/** Serves one already-built bundle with the SPA fallback the routes need. */
const preview = (outDir: string, url: string) => ({
  command: `pnpm --filter @cipherbox/web exec vite preview --outDir ${outDir} --port ${new URL(url).port} --strictPort`,
  url,
  cwd: repoRoot,
  reuseExistingServer: !isCi,
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
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'e2e',
      testMatch: '**/smoke.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: E2E_URL },
    },
    {
      name: 'release',
      testMatch: '**/release-bundle.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: RELEASE_URL },
    },
  ],
  webServer: [preview('dist', E2E_URL), preview('dist-release', RELEASE_URL)],
});
