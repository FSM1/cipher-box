import { defineConfig } from 'vitest/config';

/**
 * The merge-blocking unit suite over the pure helpers. The live suite runs
 * under `test:e2e`, because the workspace `Test` gate runs no suite that needs
 * a stack.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
  },
});
