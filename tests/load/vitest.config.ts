import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 600_000, // 10 min — load tests are long-running
    hookTimeout: 120_000,
    sequence: { concurrent: false },
    fileParallelism: false,
  },
});
