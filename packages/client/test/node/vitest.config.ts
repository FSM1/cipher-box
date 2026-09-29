import { defineConfig } from 'vitest/config';

/**
 * The Node suite runs the client against the real WASM module that
 * `build:wasm-conformance` writes to `test/browser/pkg`, so it runs after that
 * build, in the Client Browser Suite job.
 */
export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ['**/*.test.ts'],
    environment: 'node',
  },
});
