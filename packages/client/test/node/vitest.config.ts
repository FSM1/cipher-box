import { defineConfig } from 'vitest/config';

/**
 * The Node suite runs the client against the real WASM module that
 * `test:node` builds into `test/browser/pkg`.
 */
export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ['**/*.test.ts'],
    environment: 'node',
  },
});
