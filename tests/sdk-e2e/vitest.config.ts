import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 120_000,
    hookTimeout: 60_000,
    sequence: { concurrent: false },
    fileParallelism: false,
  },
});
