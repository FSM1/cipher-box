import { defineConfig } from 'vitest/config';
import { swcPlugin } from './vitest.swc';

// The scheduled tier (blueprint/testing.md: Dispatch / scheduled). Long-horizon
// liveness soaks — the republisher walk against a compressed-EOL profile — run
// over virtual time here, NOT in the per-PR gate. Triggered by cron/dispatch
// (`.github/workflows/scheduled-liveness.yml`); the unit config excludes these
// `*.scheduled.test.ts` files.
export default defineConfig({
  test: {
    include: ['src/**/*.scheduled.test.ts'],
    environment: 'node',
    testTimeout: 60_000,
  },
  plugins: [swcPlugin()],
});
