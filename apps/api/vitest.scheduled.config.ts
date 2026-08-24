import { defineConfig } from 'vitest/config';
import { swcPlugin } from './vitest.swc';

// The scheduled tier (blueprint/testing.md: Dispatch / scheduled). Long-horizon
// liveness soaks — the republisher walk against a compressed-EOL profile — run
// here, NOT in the per-PR gate. Two profiles: an in-process one over virtual
// time, and a stack one over HTTP against the booted CI stack. Triggered by
// cron/dispatch (`.github/workflows/scheduled-liveness.yml`), which boots that
// stack; the unit config excludes these `*.scheduled.test.ts` files.
//
// Serialized: the stack profile asserts on process-wide gauges of the one API
// it shares with every other file in the tier.
export default defineConfig({
  test: {
    include: ['src/**/*.scheduled.test.ts'],
    environment: 'node',
    fileParallelism: false,
    testTimeout: 60_000,
  },
  plugins: [swcPlugin()],
});
