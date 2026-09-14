// The web e2e suite (blueprint/testing.md "E2E"). The local projects run
// against the production static build, served from a built directory — the
// artifact that ships is the artifact tested. `e2e` drives the build carrying
// the introspection hook; `release` drives the same build without the flag.
//
// `E2E_SUITE` picks the slice: `smoke` (the default) is the PR gate's
// bounded-minutes budget and drops every `@full`-tagged test; `full` is the main
// gate and runs everything.
//
// `E2E_BASE_URL` switches the whole run onto the deployed front instead: no
// local server, the `staging` project only, and the real login the staging
// profiles need (`staging/README` and blueprint/testing.md staging release
// gates).
//
// `retries: 0` is policy in every slice, not tuning: a flaky test is a defect.
import { defineConfig, devices } from '@playwright/test';

const suite = process.env.E2E_SUITE ?? 'smoke';
// Reject an unrecognized value rather than silently running the smaller slice.
if (suite !== 'smoke' && suite !== 'full') {
  throw new Error(`E2E_SUITE must be smoke | full; got "${suite}"`);
}

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

const stagingBaseUrl = process.env.E2E_BASE_URL?.trim();

/**
 * The deployed front, driven through the real login. Staging is a 2-vCPU box
 * behind a rate limit keyed on the caller address, so the run is serial.
 */
const staging = {
  workers: 1,
  fullyParallel: false,
  timeout: 300_000,
  projects: [
    {
      name: 'staging-media',
      testDir: './staging',
      testMatch: '**/media.setup.ts',
    },
    {
      name: 'staging',
      testDir: './staging',
      testIgnore: '**/*.setup.ts',
      dependencies: ['staging-media'],
      use: {
        ...devices['Desktop Chrome'],
        baseURL: stagingBaseUrl,
        // No trace: this run holds a real session, and its report is an
        // artifact of a public repository. A trace records every request
        // header, which here carries the session bearer and the accelerator
        // pseudonym — a gateway credential (blueprint/api.md Egress).
        trace: 'off' as const,
      },
    },
  ],
};

const local = {
  // Every test cold-starts its own vault from a fresh login secret, so nothing
  // is shared to serialize around.
  fullyParallel: true,
  timeout: 120_000,
  projects: [
    {
      name: 'e2e',
      // Everything but the bundle-shape spec, so a new spec is in the gate the
      // moment it lands rather than on remembering to widen a list.
      testIgnore: '**/release-bundle.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: url(E2E_PORT) },
    },
    {
      name: 'release',
      testMatch: '**/release-bundle.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: url(RELEASE_PORT) },
    },
  ],
  webServer: [preview('dist', E2E_PORT, true), preview('dist-release', RELEASE_PORT)],
};

export default defineConfig({
  testDir: './tests',
  forbidOnly: isCi,
  grepInvert: suite === 'smoke' ? /@full/ : undefined,
  retries: 0,
  reporter: isCi ? [['list'], ['html', { open: 'never' }]] : 'list',
  ...(stagingBaseUrl ? staging : local),
  use: {
    // Chrome's own headless, not Playwright's default `chrome-headless-shell`:
    // the shell segfaults on a page that registers a Service Worker, killing the
    // browser under whichever assertion is in flight.
    channel: 'chromium',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
