import { defineConfig } from 'vitest/config';
import { swcPlugin } from './vitest.swc';

// The real-Postgres integration suite (blueprint/testing.md law 1: every suite
// blocks a merge in a named gate). Runs only `*.itest.ts` against a live
// Postgres in the dedicated `API Integration (real Postgres)` CI job. Each file
// provisions its own throwaway database via src/testing/integration-db.ts, so no
// cross-file isolation is needed, but keep a single worker to bound concurrent
// DB connections.
export default defineConfig({
  test: {
    include: ['src/**/*.itest.ts'],
    environment: 'node',
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
  plugins: [swcPlugin()],
});
